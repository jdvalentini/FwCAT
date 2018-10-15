const log = require('electron-log');
const network = require(__dirname + '/lib/network.js')
const cisco = require(__dirname + '/lib/parser-cisco.js')

module.exports = {
    parseFirewall: parseFirewall,
    parseLine: parseLine,
}

function detectType(configFile){
    // This function will eventually autodetect the firewall type - DEVELOPEMENT PENDING
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
        config = cisco.typedParseLine(line, parents, aceNumber)
        return {h:config.h, k:config.k, sk:config.sk, v:config.v}
    }
    else {throw 'No valid Firewall type detected'}
}