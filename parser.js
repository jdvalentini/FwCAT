const log = require('electron-log');
const network = require(__dirname + '/lib/network.js')
const cisco = require(__dirname + '/lib/parser-cisco.js')

module.exports = {
    parseFirewall: parseFirewall,
    parseLine: parseLine,
}

function detectType(configFile){
    // This function will eventually autodetect the firewall type
    return('cisco-asa')
}

function parseFirewall(configFile){
    const fs = require('fs')
    // const util = require('util')
    // const stream = require('stream')
    const es = require('event-stream')

    var lineNr = 0;
    var parents = []        // Blockify array
    var cfg = {
        host:{},            // Stores Host information: hostname, domain, Serial #, etc.
        users:[],           // Stores users defined in the config file.
        interfaces:[],      // Stores an array of interface objects with their properties.
        rules:{
            nat:[],         // NAT rules
            filter:[]       // Filter rules
        },
        notparsed:[],       // Lines that could not be understood
        objects:[],         // CISCO ASA: Network and Service Objects
        objectgroups:[]     // CISCO ASA: Object Groups
    }
    cfg.host.fwType = detectType(configFile)
    
    // var s = fs.createReadStream(configFile)
    return new Promise((resolve, reject) => { var s = fs.createReadStream(configFile)
        .pipe(es.split())
        .pipe(es.mapSync(function(line){ // change to arrow
            s.pause();

            lineNr += 1;
            ACEnumber = cfg.rules.filter.length + 1

            let {h, k, sk, v} = parseLine(cfg.host.fwType, line, parents, ACEnumber) // Gets hierarchy, key, subkey and value
            if (cfg.host.fwType == 'cisco-asa') {
                if (h >= 0) {
                    parents[h] = line
                    if (parents.length > h+1){parents = parents.slice(0,h+1)} // Clean parents from lower hierarchies
                }

                if (k == 'objects'){
                    if (sk == 'parent'){cfg[k].push(Object.assign({lineNumber:lineNr},v))}
                    else if (v.nat !== undefined){ // NAT parsing is very limited so far, it will be improved in the future
                        var found = false
                        for (i in cfg.objects){
                            if (cfg.objects[i].id == v.object && !found){
                                found = true
                                cfg.objects[i].nat = v.nat
                            }
                            else if (cfg.objects[i].id == v.object && found){
                                cfg.objects.splice(i,1)
                            }
                        }
                    }
                    else {cfg[k][cfg[k].length-1] = Object.assign(cfg[k][cfg[k].length-1],v)} // Update the last "object" element
                    // if (sk !== 'parent')
                }
                else if (k == 'objectgroups'){
                    if (sk == 'parent'){cfg[k].push(Object.assign({lineNumber:lineNr, objects:[]},v))}
                    else {
                        if (v.type == 'description'){cfg[k][cfg[k].length-1].description = v.description}
                        else {cfg[k][cfg[k].length-1]['objects'].push(v)}
                    }
                }
                else if (k == 'rules') {
                    if (sk == 'filter' && v.number !== undefined){cfg[k][sk].push(Object.assign({lineNumber:lineNr},v))}
                    else if (sk == 'nat'){cfg[k][sk].push(Object.assign({lineNumber:lineNr},v))}
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
                resolve(cfg)
            })
        );
    })
}





function parseLine(type, line, parents, aceNumber){
    aceNumber = aceNumber || 0
    if (type == 'cisco-asa'){
        // returns {h:hierarcy, k:key, sk:subkey, v:value}
        // var h = line.search(/\S|$/) // Counts whitespaces to detect the hierarchy (No error if blank)
        var h = line.search(/\S/) // Counts whitespaces to detect the hierarchy

        // Parse based on first word of parent
        if (line.search('object ') == 0) {return {h:h, k:'objects', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
        if (line.search('object-group ') == 0) {return {h:h, k:'objectgroups', sk:'parent', v:{id:line.split(' ')[2], type:line.split(' ')[1]}}}
        if (line.search('access-list ') == 0) {return {h:h, k:'rules', sk:'filter', v:cisco.parseAccessList(line,aceNumber,parents[h])}}
        if (line.search('interface ') == 0) {return {h:h, k:'interfaces', sk:'id', v:line.split(' ')[1]}}
        if (line.search('hostname ') == 0) {return {h:h, k:'host', sk:'hostname', v:line.split(' ')[1]}}
        if (line.search('domain-name ') == 0) {return {h:h, k:'host', sk:'domain', v:line.split(' ')[1]}}
        if (line.search('nat ') == 0) {return {h:h, k:'rules', sk:'nat',v:cisco.parseNAT(line,h)}}

        if (h > 0) { // Line is a child inside a block
            l = line.trim()
            if (l.search('no ') == 0) {return {h:h, k:null, sk:null, v:null}} // See how to handle no...

            var p = parseLine(type, parents[h-1], parents)  // Recursively parse the parent line

            if (p.k == 'objects') {                     // If Parent.key is 'objects'
                if (/^description /.test(l)) {var ret={description:l.split(' ').slice(1).join(' ')}}
                else if (p.v.type == 'network'){
                    if (/^host /.test(l)) {var ret={address:l.split(' ')[1], syntax:'host'}}
                    else if (/^subnet /.test(l)) {var ret={address:l.split(' ')[1]+'/'+network.mask2cidr(l.split(' ')[2]), syntax:'subnet'}}
                    else if (/^range /.test(l)) {var ret={address:l.split(' ').slice(1,3).join('-'), syntax:'range'}}
                    else if (/^fqdn /.test(l)) {var ret={address:l.split(' ')[l.split(' ').length-1], syntax:'fqdn'}}
                    else if (/^nat/.test(l)) {var ret=cisco.parseNAT(l,h,p.v.id)}
                }
                else if (p.v.type = 'service') {
                    if (/^service icmp[6]? .+/.test(l)) {var ret={type:l.split(' ')[1], protocol:l.split(' ')[1], options:l.split(' ').slice(2).join(' ')}}
                    else if (/^service icmp[6]?$/.test(l)) {var ret={type:l.split(' ')[1], protocol:l.split(' ')[1]}}
                    else if (/^service (tcp|udp|sctp) /) {var ret = cisco.parseInlineProtocol(l)}
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
// Write parse and test for service groups
                    if (/^service-object object /.test(l)) {var ret = {type:'object', id:l.split(' ')[2]}}
                    else if (/^service-object icmp[6]? .+/.test(l)) {
                        var ret = {type:l.split(' ')[1],options:l.split(' ').slice(2).join(' ')}
                    }
                    else if (/^service-object icmp[6]?/.test(l)) {var ret = {type:l.split(' ')[1]}}
                    else if (/^service-object (tcp|udp|tcp-udp|sctp) /.test(l)) {var ret = cisco.parseInlineProtocol(l)}
                    else if (/^service-object /.test(l)) {var ret = {type: 'protocol', protocol: l.split(' ')[1]}}
                    else if (/^port-object /.test(l)) {
                        if (parents[h-1].split(' ').length == 4) {
                            var ret = {type: 'port', protocol: parents[h-1].split(' ')[3], port: cisco.translateOperators(l.split(' ').slice(1).join(' '))}
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
    throw error // Check if this is right and how to catch on the call
}

// function mask2cidr(mask){
//     var cidr = ''
//     for (m of mask.split('.')) {
//         if (parseInt(m)>255) {throw 'ERROR: Invalid Netmask'}
//         if (parseInt(m)>0 && parseInt(m)<128) {throw 'ERROR: Invalid Netmask'}
//         cidr+=(m >>> 0).toString(2)
//     }
//     // Condition to check for validity of the netmask
//     if (cidr.substring(cidr.search('0'),32).search('1') !== -1) {
//         throw 'ERROR: Invalid Netmask ' + mask
//     }
//     return cidr.split('1').length-1
// }

// function isIPv4(ip) {
//     if (typeof ip !== 'string') {return false}
//     if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(ip)) {
//         for (octet of ip.split('.')) {
//             if (parseInt(octet)>255 || parseInt(octet)<0) {return false}
//         }
//         return true
//     }
//     return false
// } 

// function isIPv6(ip){
//     if (typeof ip !== 'string') {return false}
//     reg = /^((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}((\|[0-9]{0,2}))$/
//     return reg.test(ip) // Test if this works for real in every case...
// }