const network = require(__dirname + '/network.js')

module.exports = {
    parseNAT: parseNAT,
    parseAccessListAddresses: parseAccessListAddresses,
    translateOperators: translateOperators,
    parseInlineProtocol: parseInlineProtocol,
    parseAccessList: parseAccessList,
    typedParseLine: typedParseLine,
    interpretResults: interpretResults,
}

function parseNAT(line,hierarchy,object){               // Receives the configuration line for a NAT and the object affected if applicable
    // NAT parsing is in an early stage of developement
    object = object || 'No-Object-Defined'
    var nat = {}
    nat['realInterface'] = line.split('(')[1].split(',')[0]
    nat['mappedInterface'] = line.split(',')[1].split(')')[0]
 
    if(hierarchy == 0) {return nat}
    else {return {object:object, nat:nat}}
}

function parseRoutes(ln){                               // Receives the configuration line for a route
    var pieces = ln.split(' ')
    if (pieces[2] == '0.0.0.0' && pieces[3] == '0.0.0.0') {var ip = 'default'}
    else if (network.isIPv4(pieces[2])) {var ip = pieces[2] + '/' + network.mask2cidr(pieces[3])}
    else return {k:null, sk:null, v:null}
    return {k:'routes', sk:null, v:{interface:pieces[1], destination:ip, via:pieces[4], metric:pieces[5]}}
}

function parseAccessListAddresses(argList){             // Receives the split access-list config line from the address definition
    data = {shift:0}
    if (/any|any4|any6/.test(argList[0])) {data.address = argList[0]; data.shift = 1}
    else if (/interface/.test(argList[0])) {data.interface = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/object|object-group/.test(argList[0])) {data.address = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/host/.test(argList[0])) {data.address = argList[1]; data.shift = 2}
    else if (network.isIPv4(argList[0])) {data.address = argList[0]+'/'+network.mask2cidr(argList[1]); data.shift = 2}
    else if (network.isIPv6(argList[0])) {data.address = argList[0]; data.shift = 1}
    return data
}

function translateOperators(command){                   // Receives port definition ('gt 1024', 'range 21 25', etc)
    parts = command.split(' ')
    if (parts[0] == 'lt'){return '<' + parts[1]}
    if (parts[0] == 'gt'){return '>' + parts[1]}
    if (parts[0] == 'eq'){return parts[1]}
    if (parts[0] == 'neq'){return '!' + parts[1]}
    if (parts[0] == 'range'){return parts[1] + '-' + parts[2]}
}

function parseInlineProtocol(line){                     // Receives string from the source/destination sections of an access list
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

function parseAccessList(ln,aceNumber,previousLine){    // Receives current and previous line plus ACE number (order)
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
            var accessListComments = parseAccessList(previousLine, aceNumber) // Recursively check for comment
            if (accessListComments.acl == ace.acl) {ace.comment = accessListComments.comment}
        }
        // Check the type of rule
        // if (expanded[0] == 'extended') {
        if (/(extended|standard)/.test(expanded[0])){
            // ace.type = 'extended'
            ace.type = expanded.shift()
            // ace.action = expanded[1]; expanded = expanded.slice(2)
            ace.action = expanded.shift()

            // Check the protocol
            // if (/object|object-group/.test(expanded[0])) {
            if (ace.type == 'standard'){ace.protocol = 'ip'}
            else if (/object|object-group/.test(expanded[0])) {
                ace.protocol = expanded.slice(0,2).join(' ')
                expanded = expanded.slice(2)
            }
            else {ace.protocol = expanded.shift()}

            // Check the source address (Standard ACLs only support destination address)
            if (ace.type !== 'standard'){
                source = parseAccessListAddresses(expanded)
                if (source.address !== undefined) {ace.srcAddress = source.address}
                else if (source.interface !== undefined) {ace.srcInterface = source.interface}
                expanded = expanded.slice(source.shift)
            }

            // Check the source port
            if (ace.protocol !== 'ip'){
                isAddress = (/any[46]?|interface|object|object-group|host/.test(expanded[2]) || network.isIPv4(expanded[2]) || network.isIPv6(expanded[2]))
                if ((r = /(lt|gt|eq|neq|range)/.exec(expanded[0])) !== null) {
                    ace.srcPort = translateOperators(expanded.join(' '))
                    expanded = expanded.slice(2)
                    if (r[1] == 'range') {expanded.shift()}
                }
                else if (/object-group/.test(expanded[0]) && expanded.length > 2 && !isAddress) {
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
            if (ace.protocol !== 'ip'){
                if ((r = /(lt|gt|eq|neq|range)/.exec(expanded[0])) !== null) {
                    ace.dstPort = translateOperators(expanded.join(' '))
                    expanded = expanded.slice(2)
                    if (r[1] == 'range') {expanded.shift()}
                }
                else if (/object-group/.test(expanded[0])) {ace.dstPort = expanded.slice(0,2).join(' '); expanded = expanded.slice(2)}
            }

            // Remaining and unparsed options (used for development and debugging also)
            if (expanded.length > 0) {ace.options = expanded.join(' ')}
        }
        // else if (expanded[0] == 'standard') {
        //     ace.type = 'standard'
        //     ace.action = expanded[1]; expanded = expanded.slice(2)
        //     ace.protocol = 'ip'
        //     // In 'standard' rules only destination address is possible
        //     destination = parseAccessListAddresses(expanded)
        //     if (destination.address !== undefined) {ace.dstAddress = destination.address}
        //     else if (destination.interface !== undefined) {ace.dstInterface = destination.interface}
        //     // expanded = expanded.slice(destination.shift)
        // }
    }
    return ace
}


function typedParseLine(line, parents, aceNumber){
    var h = line.search(/\S/) // Counts whitespaces to detect the hierarchy

    // Parse based on first word of parent
    if (/^!|^$/.test(line)) {return {h:h, k:'discard', sk:null, v:null}}
    // if (line.search('object ') == 0) {return {h:h, k:'objects', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
    // if (line.search('object-group ') == 0) {return {h:h, k:'objectgroups', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
    if ((r = /^(object|object-group)\s([\w-]+)\s([\w-\.]+)/.exec(line)) !== null) {return {h:h, k:r[1].replace('-','')+'s', sk:'parent', v:{id:r[3], type:r[2]}}}
    if (line.search('access-list ') == 0) {return {h:h, k:'rules', sk:'filter', v:parseAccessList(line,aceNumber,parents[h])}}
    if (line.search('interface ') == 0) {return {h:h, k:'interfaces', sk:'id', v:line.split(' ')[1]}}
    // if (line.search('hostname ') == 0) {return {h:h, k:'host', sk:'hostname', v:line.split(' ')[1]}}
    // if (line.search('domain-name ') == 0) {return {h:h, k:'host', sk:'domain', v:line.split(' ')[1]}}
    if (line.search('nat ') == 0) {return {h:h, k:'rules', sk:'nat',v:parseNAT(line,h)}}
    if (line.search('route ') == 0) {return Object.assign({h:h},parseRoutes(line))}
    // if (/^: Serial Number:/.test(line)) {return {h:h, k:'host', sk:'serial', v: line.replace(/^:.*:[ ]*(\w+).*/,'$1')}}
    if ((r = /^: Serial Number:\s*(\w+).*/.exec(line)) !== null) {return {h:h, k:'host', sk:'serial', v:r[1]}}
    // if (/^: Hardware:/.test(line)) {return {h:h, k:'host', sk:'model', v: line.replace(/^:.*:[ ]*(\w+).*/,'$1')}}
    if ((r = /^: Hardware:\s*(\w+).*/.exec(line)) !== null) {return {h:h, k:'host', sk:'model', v:r[1]}}
    // if (/^dns domain-lookup /.test(line)) {return {h:h, k:'interface', sk:'dnslookup', v:line.replace(/^dns domain-lookup (.+)/,'$1')}}
    if ((r = /^dns domain-lookup (.+)/.exec(line)) !== null) {return {h:h, k:'interfaces', sk:'dnslookup', v:r[1]}}
    // if (/^dns server-group (.+)/.test(line)) {return {h:h, k:'dns', sk:'group', v:line.replace(/^dns server-group (.+)/,'$1')}}
    if ((r = /^dns server-group (.+)/.exec(line)) !== null) {return {h:h, k:'dns', sk:'group', v:r[1]}}
    if ((r = /^(hostname|domain-name)\s(.*)\s*/.exec(line)) !== null) {return {h:h, k:'host', sk:r[1].replace('-',''), v:r[2]}}
    if (/^:/.test(line)) {return {h:h, k:'discard', sk:null, v:null}}


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
        else if (p.k == 'dns'){
            // var regex = /^name-server (\d+\.\d+\.\d+\.\d+) (.+)/
            // if (regex.test(l)) {
            //     return {h:h, k:'interfaces', sk:'dns', v:{interface:l.replace(regex,'$2'), dns:l.replace(regex,'$1')}}
            // }
            if ((r = /^name-server (\d+\.\d+\.\d+\.\d+) (.+)/.exec(l)) !== null) {return {h:h, k:'interfaces', sk:p.k, v:{interface:r[2], dns:r[1]}}}
        }
    }
    return {h:h, k:null, sk:null, v:null}
}

function interpretResults(hierarchy, key, subkey, value, configJSON, lineNr, line, parents){
    if (hierarchy >= 0) {
        parents[hierarchy] = line
        if (parents.length > hierarchy+1){parents = parents.slice(0,hierarchy+1)} // Clean parents from lower hierarchies
    }

    if (key == 'objects'){
        if (subkey == 'parent'){configJSON[key].push(Object.assign({lineNumber:lineNr},value))}
        else if (value.nat !== undefined){ // NAT parsing is very limited so far, it will be improved in the future
            var found = false
            for (i in configJSON.objects){
                if (configJSON.objects[i].id == value.object && !found){
                    found = true
                    configJSON.objects[i].nat = value.nat
                }
                else if (configJSON.objects[i].id == value.object && found){
                    configJSON.objects.splice(i,1)
                }
            }
        }
        else {configJSON[key][configJSON[key].length-1] = Object.assign(configJSON[key][configJSON[key].length-1],value)} // Update the last "object" element
        // if (subkey !== 'parent')
    }
    else if (key == 'objectgroups'){
        if (subkey == 'parent'){configJSON[key].push(Object.assign({lineNumber:lineNr, objects:[]},value))}
        else {
            if (value.type == 'description'){configJSON[key][configJSON[key].length-1].description = value.description}
            else {configJSON[key][configJSON[key].length-1]['objects'].push(value)}
        }
    }
    else if (key == 'rules') {
        if (subkey == 'filter' && value.number !== undefined){configJSON[key][subkey].push(Object.assign({lineNumber:lineNr},value))}
        else if (subkey == 'nat'){configJSON[key][subkey].push(Object.assign({lineNumber:lineNr},value))}
    }
    else if (key == 'interfaces') {
        if (subkey == 'id') {var obj = {}; obj[subkey] = value; configJSON[key].push(obj)}
        else if (subkey == 'dnslookup') {
            for (i in configJSON.interfaces){
                if (configJSON.interfaces[i].nameif == value) {configJSON.interfaces[i].dnslookup = 'enabled'}
            }
        }
        else if (subkey == 'dns'){
            for (i in configJSON.interfaces){
                if (configJSON.interfaces[i].nameif == value.interface) {
                    if (configJSON.interfaces[i].dns == undefined) {configJSON.interfaces[i].dns = [value.dns]}
                    else {configJSON.interfaces[i].dns.push(value.dns)}
                }
            }
        }
        else {configJSON[key][configJSON[key].length-1][subkey] = value}  // Update the last "interface" array element
    }
    else if (key == 'routes') {configJSON[key].push(value)}
    else if (key == 'host') {configJSON[key][subkey] = value}
    else if (key == null) {configJSON.notparsed.push(line)}


    return {cfg:configJSON, parents:parents}
}