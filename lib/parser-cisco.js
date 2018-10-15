const network = require(__dirname + '/network.js')

module.exports = {
    parseNAT: parseNAT,
    parseAccessListAddresses: parseAccessListAddresses,
    translateOperators: translateOperators,
    parseInlineProtocol: parseInlineProtocol,
    parseAccessList: parseAccessList,
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