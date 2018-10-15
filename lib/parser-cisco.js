const network = require(__dirname + '/network.js')

module.exports = {
    parseNAT: parseNAT,
    parseAccessListAddresses: parseAccessListAddresses,
    translateOperators: translateOperators,
    parseInlineProtocol: parseInlineProtocol,
    parseAccessList: parseAccessList,
    typedParseLine: typedParseLine,
}

function parseNAT(line,hierarchy,object){
    // NAT parsing is in an early stage of developement
    object = object || 'No-Object-Defined'
    var nat = {}
    nat['realInterface'] = line.split('(')[1].split(',')[0]
    nat['mappedInterface'] = line.split(',')[1].split(')')[0]
 
    if(hierarchy == 0) {return nat}
    else {return {object:object, nat:nat}}
}

function parseAccessListAddresses(argList){ // Receives the splitted access-list config line from the address definition
    data = {shift:0}
    if (/any|any4|any6/.test(argList[0])) {data.address = argList[0]; data.shift = 1}
    else if (/interface/.test(argList[0])) {data.interface = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/object|object-group/.test(argList[0])) {data.address = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/host/.test(argList[0])) {data.address = argList[1]; data.shift = 2}
    else if (network.isIPv4(argList[0])) {data.address = argList[0]+'/'+network.mask2cidr(argList[1]); data.shift = 2}
    else if (network.isIPv6(argList[0])) {data.address = argList[0]; data.shift = 1}
    return data
}

function translateOperators(command){
    parts = command.split(' ')
    if (parts[0] == 'lt'){return '<' + parts[1]}
    if (parts[0] == 'gt'){return '>' + parts[1]}
    if (parts[0] == 'eq'){return parts[1]}
    if (parts[0] == 'neq'){return '!' + parts[1]}
    if (parts[0] == 'range'){return parts[1] + '-' + parts[2]}
}

function parseInlineProtocol(line){
    pieces = line.split(' ').slice(2)
    var result = {type: 'ports', protocol:line.split(' ')[1]}
    while (pieces.length > 0){
        if (/source|destination/.test(pieces[0])){
            if (/lt|gt|eq|neq|range/){
                result[pieces[0]] = translateOperators(pieces.slice(1).join(' '))
                pieces = pieces.slice(2)
            }
            else if (/range/.test(pieces[0])){
                result[pieces[0]] = translateOperators(pieces.slice(1).join(' '))
                pieces = pieces.slice(3)
            }
        }
        else {pieces.shift()}
    }
    return result
}

function parseAccessList(ln,aceNumber,previousLine){
    previousLine = previousLine || ''
    var expanded = ln.trim().split(' ').slice(2)
    var ace = {acl:ln.split(' ')[1], line:ln}

    if (expanded[0] == 'remark') {
        ace.comment = expanded.slice(1).join(' ')
        return ace
    }
    else {
        // ACE order numer
        ace.number = aceNumber
        if (previousLine.trim().split(' ')[2] == 'remark') {
            var accessListComments = parseAccessList(previousLine) // Recursively check for comment
            if (accessListComments.acl == ace.acl) {ace.comment = accessListComments.comment}
        }
        // Check the type of rule
        if (expanded[0] == 'extended') {
            ace.type = 'extended'
            ace.action=expanded[1]; expanded = expanded.slice(2)
            // Check the protocol
            if (ace.protocol == undefined){ 
                if (/object|object-group/.test(expanded[0])){ace.protocol = expanded.slice(0,2).join(' '); expanded.shift(); expanded.shift()}
                else {ace.protocol = expanded[0]; expanded.shift()}
            }

            // Check the source address
            source = parseAccessListAddresses(expanded)
            if (source.address !== undefined) {ace.srcAddress = source.address}
            else if (source.interface !== undefined) {ace.srcInterface = source.interface}
            expanded = expanded.slice(source.shift)

            // Check the source port
                // To detect the object-groups I will need to have them parsed first (should be an object-group service)
            if (ace.protocol !== 'ip'){
                testaddress = (/any[46]?|interface|object|object-group|host/.test(expanded[2]) || network.isIPv4(expanded[2]) || network.isIPv6(expanded[2]))
                if (/lt|gt|eq|neq/.test(expanded[0])){ace.srcPort = expanded.slice(0,2).join(' '); expanded = expanded.slice(2)}
                else if (/range/.test(expanded[0])) {ace.srcPort = expanded.slice(0,3).join(' '); expanded = expanded.slice(3)}
                else if (/object-group/.test(expanded[0]) && expanded.length > 2 && !testaddress) {
                    ace.srcPort = expanded.slice(0,2).join(' ');
                    expanded = expanded.slice(2)
                }
            }

            // Check the destination address
            destination = parseAccessListAddresses(expanded)
            if (destination.address !== undefined) {ace.dstAddress = destination.address}
            else if (destination.interface !== undefined) {ace.dstInterface = destination.interface}
            expanded = expanded.slice(destination.shift)

            // Check the destination port
                // To detect the object-groups I will need to have them parsed first (should be an object-group service)
            if (/lt|gt|eq|neq/.test(expanded[0])){ace.dstPort = expanded.slice(0,2).join(' '); expanded = expanded.slice(2)}
            else if (/range/.test(expanded[0])) {ace.dstPort = expanded.slice(0,3).join(' '); expanded = expanded.slice(3)}
            else if (/object-group/.test(expanded[0])) {ace.dstPort = expanded.slice(0,2).join(' '); expanded = expanded.slice(2)}

            if (expanded.length > 0) {ace.options = expanded.join(' ')}}
        else if (expanded[0] == 'standard') {
            ace.type = 'standard'
            ace.action=expanded[1]; expanded = expanded.slice(2)
            ace.protocol = 'ip'
            // In 'standard' rules only destination address is possible
            destination = parseAccessListAddresses(expanded)
            if (destination.address !== undefined) {ace.dstAddress = destination.address}
            else if (destination.interface !== undefined) {ace.dstInterface = destination.interface}
            expanded = expanded.slice(destination.shift)
        }
    }
    return ace
}


function typedParseLine(line, parents, aceNumber){
    // var h = line.search(/\S|$/) // Counts whitespaces to detect the hierarchy (No error if blank)
    var h = line.search(/\S/) // Counts whitespaces to detect the hierarchy

    // Parse based on first word of parent
    if (line.search('object ') == 0) {return {h:h, k:'objects', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
    if (line.search('object-group ') == 0) {return {h:h, k:'objectgroups', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
    if (line.search('access-list ') == 0) {return {h:h, k:'rules', sk:'filter', v:parseAccessList(line,aceNumber,parents[h])}}
    if (line.search('interface ') == 0) {return {h:h, k:'interfaces', sk:'id', v:line.split(' ')[1]}}
    if (line.search('hostname ') == 0) {return {h:h, k:'host', sk:'hostname', v:line.split(' ')[1]}}
    if (line.search('domain-name ') == 0) {return {h:h, k:'host', sk:'domain', v:line.split(' ')[1]}}
    if (line.search('nat ') == 0) {return {h:h, k:'rules', sk:'nat',v:parseNAT(line,h)}}

    if (h > 0) { // Line is a child inside a block
        l = line.trim()
        if (l.search('no ') == 0) {return {h:h, k:null, sk:null, v:null}} // See how to handle no...

        var p = typedParseLine(parents[h-1], parents, aceNumber)  // Recursively parse the parent line

        if (p.k == 'objects') {                     // If Parent.key is 'objects'
            if (/^description /.test(l)) {var ret={description:l.split(' ').slice(1).join(' ')}}
            else if (p.v.type == 'network'){
                if (/^host /.test(l)) {var ret={address:l.split(' ')[1], syntax:'host'}}
                else if (/^subnet /.test(l)) {var ret={address:l.split(' ')[1]+'/'+network.mask2cidr(l.split(' ')[2]), syntax:'subnet'}}
                else if (/^range /.test(l)) {var ret={address:l.split(' ').slice(1,3).join('-'), syntax:'range'}}
                else if (/^fqdn /.test(l)) {var ret={address:l.split(' ')[l.split(' ').length-1], syntax:'fqdn'}}
                else if (/^nat/.test(l)) {var ret=parseNAT(l,h,p.v.id)}
            }
            else if (p.v.type = 'service') {
                if (/^service icmp[6]? .+/.test(l)) {var ret={type:l.split(' ')[1], protocol:l.split(' ')[1], options:l.split(' ').slice(2).join(' ')}}
                else if (/^service icmp[6]?$/.test(l)) {var ret={type:l.split(' ')[1], protocol:l.split(' ')[1]}}
                else if (/^service (tcp|udp|sctp) /) {var ret = parseInlineProtocol(l)}
                else if (/^service /.test(l)) {var ret = {type: 'protocol', protocol: l.split(' ')[1]}}
            }
            return {h:h, k:p.k, sk:p.v.id+'-'+p.v.type, v:ret}
        }
        else if (p.k == 'objectgroups'){
            if (/^description /.test(l)) {var ret={type:'description', description:l.split(' ').slice(1).join(' ')}}
            else if (p.v.type == 'network'){
                if (/^network-object host /.test(l)) {var ret = {type:'host', address:l.split(' ')[2]}}
                else if (/^network-object object /.test(l)) {var ret = {type:'object', id:l.split(' ')[2]}}
                else if (/^network-object /.test(l)) {
                    if (network.isIPv4(l.split(' ')[1])) {var ret = {type:'subnet', address:l.split(' ')[1]+'/'+network.mask2cidr(l.split(' ')[2])}}
                    else if (network.isIPv6(l.split(' ')[1])) {var ret = {type:'subnet', address:l.split(' ')[1]}}
                }
                else if (/^group-object /.test(l)) {var ret = {type:'group', id:l.split(' ')[1]}}
            }
            else if (p.v.type == 'service'){
                if (/^service-object object /.test(l)) {var ret = {type:'object', id:l.split(' ')[2]}}
                else if (/^service-object icmp[6]? .+/.test(l)) {
                    var ret = {type:l.split(' ')[1],options:l.split(' ').slice(2).join(' ')}
                }
                else if (/^service-object icmp[6]?/.test(l)) {var ret = {type:l.split(' ')[1]}}
                else if (/^service-object (tcp|udp|tcp-udp|sctp) /.test(l)) {var ret = parseInlineProtocol(l)}
                else if (/^service-object /.test(l)) {var ret = {type: 'protocol', protocol: l.split(' ')[1]}}
                else if (/^port-object /.test(l)) {
                    if (parents[h-1].split(' ').length == 4) {
                        var ret = {type: 'port', protocol: parents[h-1].split(' ')[3], port: translateOperators(l.split(' ').slice(1).join(' '))}
                    }
                }
                else if (/^group-object /.test(l)) {var ret = {type:'group', id:l.split(' ')[1]}}
            }
            else if (p.v.type == 'protocol'){
                if (/^protocol-object /.test(l)){var ret = {protocol:l.split(' ')[1]}}
            }
            return {h:h, k:p.k, sk:p.v.id+'-'+p.v.type, v:ret}
        }
        else if (p.k == 'interfaces') {             // If Parent.key is 'interfaces'
            if (l.search('ip ') == 0) {
                return {h:h, k:p.k, sk:'ip', v:l.split(' ')[2]+'/'+network.mask2cidr(l.split(' ')[3])}
            }
            return {h:h, k:p.k, sk:l.split(' ')[0], v:l.split(' ')[1]}
        }
    }
    return {h:h, k:null, sk:null, v:null}
}