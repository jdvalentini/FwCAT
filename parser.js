const log = require('electron-log');
const network = require(__dirname + '/lib/network.js')
const cisco = require(__dirname + '/lib/parser-cisco.js')

log.transports.console.level = false;
log.transports.file.level = 'info';

module.exports = {
    parseFirewall: parseFirewall,
    parseLine: parseLine,
    selectAccessList: selectAccessList,
    selectObjectGroup: selectObjectGroup,
    selectObject: selectObject,
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

    var lineNumber = 0;
    var parents = []        // Blockify array
    var cfg = {
        host:{},            // Stores Host information: hostname, domain, Serial #, etc.
        users:[],           // Stores users defined in the config file.
        interfaces:[],      // Stores an array of interface objects with their properties.
        rules:{
            nat:[],         // NAT rules
            filter:[]       // Filter rules
        },
        routes:[],
        notparsed:[],       // Lines that could not be understood
        objects:[],         // CISCO ASA: Network and Service Objects
        objectgroups:[]     // CISCO ASA: Object Groups
    }

    cfg.host.fwType = detectType(configFile)
    
    return new Promise((resolve, reject) => { var s = fs.createReadStream(configFile)
        .pipe(es.split())
        .pipe(es.mapSync((line) => {
            s.pause();

            lineNumber += 1;
            ACEnumber = cfg.rules.filter.length + 1

            let {h, k, sk, v} = parseLine(cfg.host.fwType, line, parents, ACEnumber) // Gets hierarchy, key, subkey and value
            if (cfg.host.fwType == 'cisco-asa') {
                results = cisco.interpretResults(h, k, sk, v, cfg, lineNumber, line, parents)
                cfg = results.cfg
                parents = results.parents
            }

            s.resume();
            })
            .on('error', function(err){
                log.error('Error while reading file.', err);
                reject(err)
            })
            .on('end', function(){
                log.info('Read entire file: ' + lineNumber + ' lines.')
                resolve(cfg)
            })
        );
    })
}


function parseLine(type, line, parents, aceNumber){
    // returns {h:hierarcy, k:key, sk:subkey, v:value}
    aceNumber = aceNumber || 0
    if (type == 'cisco-asa'){
        config = cisco.typedParseLine(line, parents, aceNumber)
        return {h:config.h, k:config.k, sk:config.sk, v:config.v}
    }
    else {throw 'No valid Firewall type detected'}
}


function selectAccessList(CONFIG, ACL){
    return CONFIG.rules.filter.filter((ACE) => {
        return ACE.acl === ACL
    })
}

function selectObjectGroup(CONFIG,GROUPNAME){
    return CONFIG.objectgroups.filter((GROUPS) => {
        return GROUPS.id === GROUPNAME
    })
}

function selectObject(CONFIG,OBJECTNAME){
    return CONFIG.objects.filter((OBJECTS) => {
        return OBJECTS.id === OBJECTNAME
    })
}