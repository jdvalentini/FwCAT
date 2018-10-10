const log = require('electron-log');

module.exports = {
    testModule: testModule,
    parseFirewall: parseFirewall,
    ciscoParseAccessList: ciscoParseAccessList,
    isIPv4: isIPv4
}

var accessListCommentBuffer = ''
var ACEnumber = 0

function testModule(message){
    console.log(message)
}

function detectType(configFile){
    // This function will eventually autodetect the firewall type
    return('cisco-asa')
}

function parseFirewall(configFile){
    const fs = require('fs')
    const util = require('util')
    const stream = require('stream')
    const es = require('event-stream')

    var lineNr = 0;
    var parents = []    // Cisco exclusive
    var fwType = detectType(configFile)
    var cfg = {
        host:{},
        users:[],
        interfaces:[],
        rules:{
            nat:[],
            filter:[]
        },
        notparsed:[]
    }
    
    // var s = fs.createReadStream(configFile)
    return new Promise((resolve, reject) => { var s = fs.createReadStream(configFile)
        .pipe(es.split())
        .pipe(es.mapSync(function(line){ // change to arrow
            s.pause();

            lineNr += 1;

            let {h, k, sk, v} = parseLine(fwType, line, parents) // Gets hierarchy, key, subkey and value
            if (fwType == 'cisco-asa') {
                if (h >= 0) {
                    parents[h] = line
                    if (parents.length > h+1){parents = parents.slice(0,h+1)} // Clean parents from lower hierarchies
                }

                if (k == 'rules') {
                    if (sk == 'filter' && v !== 'remark'){cfg[k][sk].push(Object.assign({lineNumber:lineNr},v))}
                }
                else if (k == 'interfaces') {
                    if (sk == 'id') {var obj = {}; obj[sk] = v; cfg[k].push(obj)}
                    else {cfg[k][cfg[k].length-1][sk] = v}  // Update the last "interface" array element
                }
                else if (k == 'host') {cfg[k][sk] = v}
                else {cfg.notparsed.push(line)}
            }

            s.resume();
            })
            .on('error', function(err){
                console.log('Error while reading file.', err);
                reject(err)
            })
            .on('end', function(){
                console.log('Read entire file: ' + lineNr + ' lines.')
                accessListCommentBuffer = ''
                ACEnumber = 0
                resolve(cfg)
            })
        );
    })
}

function ciscoParseAccessListAddresses(argList){ // Receives the splitted access-list config line from the address definition
    data = {shift:0}
    if (/any|any4|any6/.test(argList[0])) {data.address = argList[0]; data.shift = 1}
    else if (/interface/.test(argList[0])) {data.interface = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/object|object-group/.test(argList[0])) {data.address = argList.slice(0,2).join(' '); data.shift = 2}
    else if (/host/.test(argList[0])) {data.address = argList[1]; data.shift = 2}
    else if (isIPv4(argList[0])) {data.address = argList[0]+'/'+mask2cidr(argList[1]); data.shift = 2}
    else if (isIPv6(argList[0])) {data.address = argList[0]; data.shift = 1}
    return data
}


function ciscoParseAccessList(ln){
    // From Cisco Conf
        // access-list access_list_name [line line_number] extended {deny | permit} protocol_argument source_address_argument...
        // dest_address_argument [log [[level] [interval secs] | disable | default]] [time-range time_range_name] [inactive]
    var expanded = ln.trim().split(' ').slice(2)
    var ace = {acl:ln.split(' ')[1], line:ln}

    if (expanded[0] == 'remark') {
        ace.comment = expanded.slice(1).join(' ')
        accessListCommentBuffer = expanded.slice(1).join(' ')
        return 'remark'
    }
    else {
        // ACE order numer
        ACEnumber += 1
        ace.number = ACEnumber
        // Clear comment buffer
        ace.comment = accessListCommentBuffer
        accessListCommentBuffer = ''
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
            source = ciscoParseAccessListAddresses(expanded)
            if (source.address !== undefined) {ace.srcAddress = source.address}
            else if (source.interface !== undefined) {ace.srcInterface = source.interface}
            expanded = expanded.slice(source.shift)

            // Check the source port
                // To detect the object-groups I will need to have them parsed first (should be an object-group service)
            if (ace.protocol !== 'ip'){
                testaddress = (/any[46]?|interface|object|object-group|host/.test(expanded[2]) || isIPv4(expanded[2]) || isIPv6(expanded[2]))
                if (/lt|gt|eq|neq/.test(expanded[0])){ace.srcPort = expanded.slice(0,2).join(' '); expanded = expanded.slice(2)}
                else if (/range/.test(expanded[0])) {ace.srcPort = expanded.slice(0,3).join(' '); expanded = expanded.slice(3)}
                else if (/object-group/.test(expanded[0]) && expanded.length > 2 && !testaddress) {
                    ace.srcPort = expanded.slice(0,2).join(' ');
                    expanded = expanded.slice(2)
                }
            }

            // Check the destination address
            destination = ciscoParseAccessListAddresses(expanded)
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
            destination = ciscoParseAccessListAddresses(expanded)
            if (destination.address !== undefined) {ace.dstAddress = destination.address}
            else if (destination.interface !== undefined) {ace.dstInterface = destination.interface}
            expanded = expanded.slice(destination.shift)
        }
    }
    return ace
}

function parseLine(type, line, parents){
    if (type == 'cisco-asa'){
        // returns {h:hierarcy, k:key, sk:subkey, v:value}
        // var h = line.search(/\S|$/) // Counts whitespaces to detect the hierarchy (No error if blank)
        var h = line.search(/\S/) // Counts whitespaces to detect the hierarchy

        if (line.search('hostname ') == 0) {return {h:h, k:'host', sk:'hostname', v:line.split(' ')[1]}}
        if (line.search('domain-name ') == 0) {return {h:h, k:'host', sk:'domain', v:line.split(' ')[1]}}

        if (line.search('interface ') == 0) {return {h:h, k:'interfaces', sk:'id', v:line.split(' ')[1]}}

        if (line.search('access-list ') == 0) {return {h:h, k:'rules', sk:'filter', v:ciscoParseAccessList(line)}}

        if (h>0) { // Line is a child inside a block
            l = line.trim()
            if (l.search('no ') == 0) {return {h:h, k:null, sk:null, v:null}} // See how to handle no...

            var p = parseLine(type, parents[h-1], parents)  // Recursively parse the parent line

            if (p.k == 'interfaces') {
                if (l.search('ip ') == 0) {
                    return {h:h, k:p.k, sk:'ip', v:l.split(' ')[2]+'/'+mask2cidr(l.split(' ')[3])}
                }
                return {h:h, k:p.k, sk:l.split(' ')[0], v:l.split(' ')[1]}
            }
        }

        return {h:h, k:null, sk:null, v:null}
    }
    throw error // Check if this is right and how to catch on the call
}

function mask2cidr(mask){
    var cidr = ''
    for (m of mask.split('.')) {
        if (parseInt(m)>255) {throw 'ERROR: Invalid Netmask'}
        if (parseInt(m)>0 && parseInt(m)<128) {throw 'ERROR: Invalid Netmask'}
        cidr+=(m >>> 0).toString(2)
    }
    // Condition to check for validity of the netmask
    if (cidr.substring(cidr.search('0'),32).search('1') !== -1) {
        throw 'ERROR: Invalid Netmask ' + mask
    }
    return cidr.split('1').length-1
}

function isIPv4(ip) {
    if (typeof ip !== 'string') {return false}
    if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(ip)) {
        for (octet of ip.split('.')) {
            if (parseInt(octet)>255 || parseInt(octet)<0) {return false}
        }
        return true
    }
    return false
} 

function isIPv6(ip){
    if (typeof ip !== 'string') {return false}
    reg = /^((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}((\|[0-9]{0,2}))$/
    return reg.test(ip) // Test if this works for real in every case...
}