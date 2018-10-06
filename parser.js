module.exports = {
    testModule: testModule,
    parseFirewall: parseFirewall
}

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
        }
    }
    
    // var s = fs.createReadStream(configFile)
    return new Promise((resolve, reject) => { var s = fs.createReadStream(configFile)
        .pipe(es.split())
        .pipe(es.mapSync(function(line){ // change to arrow
            s.pause();

            lineNr += 1;

            let {h, k, sk, v} = parseLine(fwType, line, parents) // Gets hierarchy, key, subkey and value
            if (fwType == 'cisco-asa' && h >= 0) {parents[h] = line} // Se clearing children on writing parent

            if (k == 'host') {cfg[k][sk] = v}
            if (k == 'interfaces') {
                if (sk == 'id') {var obj = {}; obj[sk] = v; cfg[k].push(obj)}
                else {cfg[k][cfg[k].length-1][sk] = v}  // Update the last "interface" array element
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

function parseLine(type, line, parents){
    if (type == 'cisco-asa'){
        // h = line.search(/\S|$/) // Counts whitespaces to detect the hierarchy
        var h = line.search(/\S/) // Counts whitespaces to detect the hierarchy

        if (line.search('hostname ') == 0) {return {h:h, k:'host', sk:'hostname', v:line.split(' ')[1]}}
        if (line.search('domain-name ') == 0) {return {h:h, k:'host', sk:'domain', v:line.split(' ')[1]}}

        if (line.search('interface ') == 0) {return {h:h, k:'interfaces', sk:'id', v:line.split(' ')[1]}}

        if (h>0) { // Line is a child inside a block
            l = line.trim()
            if (l.search('no ') == 0) {return {h:h, k:null, sk:null, v:null}} // See how to handle no...

            var p = parseLine(type, parents[h-1], parents)

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
        if (parseInt(m)>255) {throw 'ERROR: Invalid Netmask'} // Check each group is 0-255
        if (parseInt(m)>0 && parseInt(m)<128) {throw 'ERROR: Invalid Netmask'}
        cidr+=(m >>> 0).toString(2)
    }
    // Condition to check for validity of the netmask
    if (cidr.substring(cidr.search('0'),32).search('1') !== -1) {
        throw 'ERROR: Invalid Netmask ' + mask
    }
    return cidr.split('1').length-1
}