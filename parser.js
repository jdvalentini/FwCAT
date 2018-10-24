/**
 * @overview FwCAT: Firewall Configuration Assessment Tool
 * @author Jorge Valentini <jdval@protonmail.com>
 * @author Esteban Panelli <https://github.com/estebanpanelli>
 * @license GPL-3.0-or-later
 * @version 0.8
 */

const log = require('electron-log');
const cisco = require(__dirname + '/lib/parser-cisco.js')

log.transports.console.level = false;
log.transports.file.level = 'info';

/**
 * Details on Firewall
 * @typedef {Object} fwcHost
 * @property {string} fwType - Firewall syntax detected by the parser
 * @property {string} [serial] - Serial number
 * @property {string} [model] - Firewall model
 * @property {string} [hostname] - Hostname
 * @property {string} [domainname] - Domain Name
 */

/**
 * System users
 * @typedef {Object} fwcUser
 * @property {string} id - User name or unique identifier
 * @property {string} [privilege] - Privilege level or codename (Depends on the firewall)
 * @property {string} [hash] - Hashed password of the user
 * @property {boolean} [encrypted] - Is the password encrypted?
 */

/**
 * System interfaces
 * @typedef {Object} fwcInterface
 * @property {string} id - Interface physical name or unique identifier
 * @property {string} [nameif] - Interface logical name
 * @property {string} [securitylevel] - Cisco security level for this interface
 * @property {string} [ip] - IP address and netmask in CIDR notation
 * @property {boolean} [dnslookup] - Is the interface allowed to send DNS requests?
 * @property {string[]} [dns] - A list of DNS servers (in order of priority)
 */

/**
 * NAT rules
 * @typedef {Object} fwcNAT
 * @property {string} realInterface - Obfuscated interface
 * @property {string} mappedInterface - Public interface
 */

/**
 * Filter Rules
 * @typedef {Object} fwcFilter
 * @property {string} acl - The name of the Access Control List
 * @property {number} lineNumber - The line number in the config file
 * @property {string} line - The line of the configuration file where this ACE is configured
 * @property {number} number - The number of Access Control Entry (Ordering)
 * @property {string} [type] - Rule classification [standard|extended]
 * @property {string} action - What happens when the rule matches [permit,deny,drop,log]
 * @property {string} protocol - Protocol matched
 * @property {string} [srcAddress] - Source Address
 * @property {string} [srcPort] - Source Port
 * @property {string} [dstAddress] - Destination Address
 * @property {string} [dstPort] - Destination Port
 * @property {string} [comment] - Comments on this rule
 */

/**
 * Rules
 * @typedef {Object} fwcRules
 * @property {fwcNAT[]} nat - List of NAT rules
 * @property {fwcFilter[]} filter - List of Filter rules
 */

/**
 * Routes
 * @typedef {Object} fwcRoute
 * @property {string} [interface] - Interface to which the route is applied
 * @property {string} destination - Destination subnet
 * @property {string} via - Gateway for this route
 * @property {string} [metric] - Route priority
 */

/**
 * Objects
 * @typedef {Object} fwcObject
 * @property {string} id - Name or unique identifier
 * @property {string} type - Type of object [network|service]
 * @property {string} address - address for the host or subnet
 * @property {string} syntax - How was the address specified
 * @property {string} description - Description of the object
 * @property {number} lineNumber - The line number in the config file
 * @property {string} protocol - Protocol (for service objects)
 * @property {string} destination - Destination port (for service objects)
 * @property {string} source - Destination port (for service objects)
 * @property {string} options - Unparsed options for general protocols such as ICMP
 */


/**
 * Object groups
 * @typedef {Object} fwcObjectgroup
 * @property {string} id - Name or unique identifier
 * @property {string} type - Type of object group [network|service]
 * @property {fwcObject[]} objects - List of objects
 */


/**
 * The results of this parser are based on an fwConfig object.
 * @typedef {Object} fwConfig
 * @property {fwcHost} host - Describes host parameters.
 * @property {fwcUser[]} users - List of users.
 * @property {fwcInterface[]} interfaces - List of interfaces.
 * @property {fwcRules} rules - Contains 2 lists for NAT and Filter rules.
 * @property {fwcNAT[]} rules.nat - List of NAT rules.
 * @property {fwcFilter[]} rules.filter - List of filter rules.
 * @property {fwcRoute[]} routes - List of routes.
 * @property {fwcObject[]} objects - List of objects.
 * @property {fwcObjectgroup[]} objectgroups - List of objectgroups.
 * @property {string[]} notparsed - List of lines that could not be parsed.
 */

/**
 * Output from interpreting parser results
 * @typedef {Object} fwcResults
 * @property {fwConfig} cfg - The current status of the config object
 * @property {string[]} parents - A list of all the parents in order of hierarchy
 */

module.exports = {
    parseFirewall: parseFirewall,
    parseLine: parseLine,
    selectAccessList: selectAccessList,
    selectObjectGroup: selectObjectGroup,
    selectObject: selectObject,
    listItems: listItems,
    selectItem: selectItem,
    listRules: listRules,
}

/**
 * Detects the type of a of a firewall by inspecting its configuration file
 * @param {string} CONFIGFILE - Full path to the configuration file
 * 
 * @returns {string} Firewall parsing routinge codename
 */
function detectType(CONFIGFILE){
    // This function will eventually autodetect the firewall type - DEVELOPEMENT PENDING
    return('cisco-asa')
}

/**
 * Parses a firewall by inspecting its configuration file
 * @param {string} CONFIGFILE - Full path to the configuration file
 * 
 * @returns {fwConfig} An object with the parsed configuration
 */
function parseFirewall(CONFIGFILE){
    const fs = require('fs')
    const es = require('event-stream')

    var lineNumber = 0;
    var parents = []        // Blockify array
    var cfg = {
        host:{},            // Stores Host information: hostname, domain, Serial #, etc.
        users:[],           // Stores users defined in the config file.
        interfaces:[],      // Stores an array of interface objects with their properties.
        rules:{
            nat:[],         // List of NAT rules
            filter:[]       // List of Filter rules
        },
        routes:[],          // Stores route objects: {interface, destination, via, metric}
        notparsed:[],       // Stores lines that could not be understood
        objects:[],         // CISCO ASA: Network and Service Objects
        objectgroups:[]     // CISCO ASA: Object Groups
    }

    cfg.host.fwType = detectType(CONFIGFILE)
    
    return new Promise((resolve, reject) => { var s = fs.createReadStream(CONFIGFILE)
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

/**
 * Results from a parsed line
 * @typedef {Object} fwcLine
 * @property {number} h - Hierarchy of the line
 * @property {string} k - Key of the fwcConfig object
 * @property {string} sk - SubKey of the fwcConfig object (when applicable)
 * @property {Object} v - Value resulting from the parsing process
 */

/**
 * Parses a firewall line by inspecting the line and its parents
 * @param {string} TYPE - The firewall parsing codename
 * @param {string} LINE - The configuration line stream
 * @param {string[]} PARENTS - A list of all the parents in order of hierarchy
 * @param {string} ACENUMBER - The ACE number (Rule processing order)
 * 
 * @returns {fwcLine} An object containing hierarchy, key, subkey and value
 */
function parseLine(TYPE, LINE, PARENTS, ACENUMBER){
    // returns {h:hierarcy, k:key, sk:subkey, v:value}
    ACENUMBER = ACENUMBER || 0
    if (TYPE == 'cisco-asa'){
        config = cisco.typedParseLine(LINE, PARENTS, ACENUMBER)
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

/**
 * Paging Information
 * @typedef {Object} fwcPagingInfo
 * @property {number} items - Number of items present in the original list
 * @property {number} pages - Pages resulting from splitting the list
 * @property {number} page - Current returned page 
 * @property {number} pagesize - Items displayed per page
 */

/**
 * Paged results of a list
 * @typedef {Object} fwcPagedResults
 * @property {fwcPagingInfo} size - Number of items and resulting pages
 * @property {Object[]} list - The sliced list of the requested length
 */

/**
 * Retrieves a slice of a given list
 * @param {Object[]} LIST - Config JSON obtained from parsing the config file
 * @param {number} [PERPAGE] - Amount of objects per page or ALL (default)
 * @param {number} [PAGE] - Page number. By default retrieves 1st page
 * 
 * @returns {fwcPagedResults} An object containing the paging information and a sliced list
 */
function splitPages(LIST,PERPAGE,PAGE){
    PAGE = PAGE || 1
    PERPAGE = PERPAGE || 'ALL'
    
    if (PERPAGE > LIST.length) {PERPAGE = 'ALL'}

    total    = LIST.length
    pages    = (PERPAGE === 'ALL') ? 1 : Math.ceil(total/PERPAGE)
    pagesize = (PERPAGE === 'ALL') ? total : PERPAGE
    if (PAGE > pages) {PAGE = pages}

    start    = (PERPAGE === 'ALL') ? 0 : PERPAGE*(PAGE-1)
    end      = (PERPAGE === 'ALL') ? total : PERPAGE*(PAGE)

    return {
        size:{items:total, pages:pages, page:PAGE, pagesize:pagesize},
        list:LIST.slice(start,end)
    }
}
/**
 * Retrieves a list of objects from the parsed config
 * @param {fwConfig} CONFIG - Config JSON obtained from parsing the config file
 * @param {string} KEY - Key to retreive, choose [objects|objectgroups|routes|interfaces|users|notparsed]
 * @param {number} [PERPAGE] - Amount of objects per page or ALL (default)
 * @param {number} [PAGE] - Page number. By default retrieves 1st page
 * 
 * @returns {object} Paged list of items of the selected key
 */
function listItems(CONFIG,KEY,PERPAGE,PAGE){
    // if (!(/objects|objectgroups|routes|interfaces|users|notparsed/.test(KEY))) {return {error:'Invalid Key'}}
    if (!(/objects|objectgroups|routes|interfaces|users|notparsed/.test(KEY))) {throw new Error('Invalid Key')}
    
    return splitPages(CONFIG[KEY],PERPAGE,PAGE)
}

/**
 * Retrieves a list of rules from the parsed config
 * @param {fwConfig} CONFIG - Config JSON obtained from parsing the config file
 * @param {string} LIST - Select the list of rules, choose [nat|filter]
 * @param {number} [PERPAGE] - Amount of objects per page or ALL (default)
 * @param {number} [PAGE] - Page number. By default retrieves 1st page
 * @param {string[]} [MATCH] - Return only objects matching MATCH[0] = MATCH[1] (MATCH is a 2 items array)
 * @param {boolean} [ISREGEX] - Is match value a regex? otherwise string
 * 
 * @returns {object} Paged list of rules of the selected list
 */
function listRules(CONFIG,LIST,PERPAGE,PAGE,MATCH,ISREGEX){
    if (!(/nat|filter/.test(LIST))) {throw new Error('Invalid rule set')}

    if (MATCH !== undefined){
        if (!(Array.isArray(MATCH)) || MATCH.length !== 2) {throw new Error('Invalid match array')}
        var matchedList = CONFIG.rules[LIST].filter((ENTRY) => {
            if (ISREGEX) return new RegExp(MATCH[1]).test(ENTRY[MATCH[0]])
            else return ENTRY[MATCH[0]] == MATCH[1]
        })
    }
    else {var matchedList = CONFIG.rules[LIST]}

    return splitPages(matchedList,PERPAGE,PAGE)
}

/**
 * Retrieves details of a given item.
 * 
 * @param {fwConfig} CONFIG - Config JSON obtained from parsing the config file
 * @param {string} KEY - Key to retreive, choose [objects|objectgroups|interfaces|users]
 * @param {string} ID - ID for the item
 * 
 * @returns {object} Paged list of items of the selected key
 */
function selectItem(CONFIG,KEY,ID){
    if (!(/objects|objectgroups|interfaces|users/.test(KEY))) {throw new Error('Invalid Key')}
    selection = CONFIG[KEY].filter((OBJECTS) => {
        return OBJECTS.id === ID
    })
    if (selection.length > 1) {return {warning:'Multiple items selected', item:selection[0], all:selection}}
    else {return {item:selection[0]}}
}