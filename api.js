/**
 * @overview Web API for firewal parsing.
 * @author Jorge Valentini <jdval@protonmail.com>
 * @license GPL-3.0-or-later
 * @version 0.1.0
 */

/**
 * @api {post} /parse Parse file
 * @apiVersion 0.1.0
 * @apiName PostParseCommand
 * @apiGroup FwCAT
 * @apiDescription Use this endpoint to parse a file and open the GET listeners serving the results.
 * 
 * @apiParam {String="parseCfg"} cmd Command to send to endpoint
 * @apiParam {String} cfgFile Full path to the configuration file to parse
 * @apiParam {Boolean} [workspace] Workspace mode: Specify if the parsed data should be part of a separate Workspace. If using the workspace mode, all the endpoints in the <a href="#api-Query">Query</a> section are available under <code>/{workspace.id}/</code>, value that is generated and returned from this POST.
 * 
 * @apiParamExample {json} Request-Example:
 *     {     "cmd": "parseCfg",
 *       "cfgFile": "/path/to/cisco.cfg" }
 * 
 * @apiExample Example usage:
 *     curl -H "Content-Type: application/json" -d '{"cmd":"parseCfg", "cfgFile":"/path/to/cisco.cfg"}' http://localhost:3000/parse
 *     # Or if you want to make use of the Workspaces feature:
 *     curl -H "Content-Type: application/json" -d '{"cmd":"parseCfg", "cfgFile":"/path/to/cisco.cfg", workspace:true}' http://localhost:3000/parse
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "status": "ready"
 *     }
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "status": "ready"
 *       "workspace": {
 *         "id": "r5j6e2dj03gzexo",
 *         "configFile": "/path/to/cisco.cfg"
 *       }
 *     }
 *
 * @apiError (Error 4xx) InvalidCommand cmd parameter is not valid
 * @apiError (Error 4xx) RepeatedFile Config is already parsed in a workspace
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 418
 *     {
 *       "error": "Command is not valid"
 *     }
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 400
 *     {
 *       "error":"File is already parsed in a workspace"
 *     }
 */

/**
 * @api {get} /hostdata Get firewall host data
 * @apiVersion 0.1.0
 * @apiName GetHostData
 * @apiGroup Query
 * @apiDescription After posting a file to parse, use this endpoint to get firewall host information.
 * 
 * @apiSuccess {String} fwType Firewall parsing syntax.
 * @apiSuccess {String} serial Serial Number.
 * @apiSuccess {String} model Firewall model.
 * @apiSuccess {String} hostname Host Name.o
 * @apiSuccess {String} domainname Firewall domain.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "fwType": "cisco-asa",
 *       "model": "ASA5545",
 *       "hostname": "ASATEST"
 *     }
 *
 * @apiError (Error 5xx) HostNotParsed The host data is not present in the parsed results or the firewall has not been parsed
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 500
 *     {
 *       "error": "The parser was unable to retrieve host data"
 *     }
 */

/**
 * @api {get} /listitems List firewall properties
 * @apiVersion 0.1.0
 * @apiName GetListItems
 * @apiGroup Query
 * @apiDescription After posting a file to parse, use this endpoint to list firewall properties.
 *
 * @apiParam {String="objects","objectgroups","routes","interfaces","users","notparsed"} key Config property to retrieve
 * @apiParam {Number} [per_page="ALL"] Split results in this amount of items per page. Use "ALL" for all
 * @apiParam {Number} [page=1] The page number. If larger than last page returns last page
 *
 * @apiExample Example usage:
 *     curl -i -s 'http://localhost:3000/listitems?key=routes&per_page=3&page=2'
 *     # Or if you want to make use of the Workspaces feature (example workspace.id = "r5j6e2dj03gzexo"):
 *     curl -i -s 'http://localhost:3000/r5j6e2dj03gzexo/listitems?key=routes&per_page=3&page=2'
 * 
 * @apiSuccess {Object[]} list List of objects for the requested property.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     Content-Type: application/json
 *     FwCAT-items: 1
 *     FwCAT-pages: 1
 *     FwCAT-page: 1
 *     FwCAT-pagesize: 1
 *     {
 *       "list": [Object1, Object2]
 *     }
 *
 * @apiError KeyMissing No list key was found.
 * @apiError (Error 5xx) ServerError Error was thrown from the parser
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 400
 *     {
 *       "error": "Key missing"
 *     }
 * 
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 500
 *     {
 *       "error": "Invalid key"
 *     }
 */

/**
 * @api {get} /selectitem Get item information
 * @apiVersion 0.1.0
 * @apiName GetSelectItem
 * @apiGroup Query
 * @apiDescription After posting a file to parse, use this endpoint get details on a given item key and id.
 *
 * @apiParam {String="objects","objectgroups","interfaces","users"} key Config property to retrieve
 * @apiParam {String} id ID of the item to match
 *
 * @apiExample Example usage:
 *     curl -s 'http://localhost:3000/selectitem?key=interfaces&id=GigabitEthernet0/0'
 * 
 * @apiSuccess {Object} item Details on the first matching item (may be the only one).
 * @apiSuccess {Object} [all] List of objects matching the query.
 * @apiSuccess {String} [warning] Warns if there is something to pay attention to.
 *
 * @apiSuccessExample Success-Response:
 *     {
 *       "item": Object
 *     }
 * 
 * @apiSuccessExample Success-Response:
 *     {
 *       "item": Object1,
 *       "warning": "Multiple items selected",
 *       "all": [Object2, Object3]
 *     }
 *
 * @apiError KeyOrIDMissing No list key was found or no ID was specified.
 * @apiError (Error 5xx) ServerError Error was thrown from the parser
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 400
 *     {
 *       "error": "ID or key missing"
 *     }
 * 
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 500
 *     {
 *       "error": "Invalid key"
 *     }
 */


/**
 * @api {get} /listrules/:key List firewall rules
 * @apiVersion 0.1.0
 * @apiName GetListRules
 * @apiGroup Query
 * @apiDescription After posting a file to parse, use this endpoint to see the list of firewall rules.
 * 
 * You can also match a rule by using any key:value pair to select only the rules matching certain criteria (for instance Destination port). Regular expresions can be used.
 *
 * @apiParam {String="filter","nat"} key ID of the set of rules
 * @apiParam {Number} [per_page="ALL"] Split results in this amount of items per page. Use "ALL" for all
 * @apiParam {Number} [page=1] The page number. If larger than last page returns last page
 * @apiParam {String} [match_key] Bring only results with this key
 * @apiParam {String} [match_value] Bring only results where match_key matches this value
 * @apiParam {Boolean} [regex] Specifies if the previous matching pair should be treated as a RegExp. In the example usage you can change match_value to <code>3?389</code> (URL encoded) and add <code>&regex=1</code> to match 389 and 3389
 *
 * @apiExample Example usage:
 *     curl -i -s 'http://localhost:3000/listrules/filter?per_page=10&page=1&match_key=dstPort&match_value=389'
 * 
 * @apiSuccess {Object[]} list List of objects matching the query.
 *
 * @apiSuccessExample Success-Response:
 *     HTTP/1.1 200 OK
 *     Content-Type: application/json
 *     FwCAT-items: 1
 *     FwCAT-pages: 1
 *     FwCAT-page: 1
 *     FwCAT-pagesize: 1
 *     {
 *       "list": [Object1, Object2]
 *     }
 *
 * @apiError KeyMissing No list key was found.
 * @apiError (Error 5xx) ServerError Error was thrown from the parser
 *
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 400
 *     {
 *       "error": "Key missing"
 *     }
 * 
 * @apiErrorExample Error-Response:
 *     HTTP/1.1 500
 *     {
 *       "error": "Invalid match array"
 *     }
 */

/**
 * @api {get} /workspaces List workspaces
 * @apiVersion 0.1.0
 * @apiName GetWorkspaces
 * @apiGroup Workspaces
 * @apiDescription Workspaces are generated when sending a parsing command with the 'workspace' flag on (See <a href="#api-FwCAT-PostParseCommand">/parse</a>).
 * 
 * The parser will return an object containing <code>{status:"ready", workspace:{id:"pdch0f7udfsnz0y", configFile:"/path/to/cisco2.cfg"}}</code>. 
 * 
 * Using the ID of the workspace obtained, you can query all the endpoints described in the <a href="#api-Query">Query</a> section, prepending the workspace ID, for instance: <code>/pdch0f7udfsnz0y/hostdata</code>.
 * 
 * By consuming this endpoint you can get the current list of active workspaces.
 * 
 * @apiSuccessExample Success-Response:
 *     [
 *       {
 *         "id": "r5j6e2dj03gzexo",
 *         "configFile": "/path/to/cisco.cfg"
 *       },
 *       {
 *         "id": "pdch0f7udfsnz0y",
 *         "configFile": "/path/to/cisco2.cfg"
 *       }
 *     ]
 */

const parser = require(__dirname + '/parser.js')
const log = require('electron-log')
const express = require('express');
const bodyParser = require('body-parser');
const app = express();

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

var workspaces = []

// app.use(express.static(path.join(__dirname, 'static')));

// Waits for POST request with the config file path --> data: {cmd:"parseCfg", cfgFile:"/path/to/file.cfg"}
app.post('/parse', function(req, res){
    log.silly('POST /parse');
    if (req.body.cmd == 'parseCfg'){
        cfg = parser.parseFirewall(req.body.cfgFile)
        cfg.then(config =>{
            if (req.body.workspace) {
                if (workspaces.filter(o => o.configFile == req.body.cfgFile).length > 0) {
                    res.writeHead(400, {'Content-Type': 'application/json'});
                    res.end(JSON.stringify({error:'File is already parsed in a workspace'}));
                } else {
                    workspaces = createWorkspace(workspaces)
                    workspaces[workspaces.length - 1].configFile = req.body.cfgFile
                    var ws = workspaces[workspaces.length - 1]
                    setupListeners(config, ws)
                    res.writeHead(200, {'Content-Type': 'application/json'});
                    res.end(JSON.stringify({status:'ready', workspace:ws}, null, 2));
                }
            }
            else {
                setupListeners(config)
                res.writeHead(200, {'Content-Type': 'application/json'});
                res.end(JSON.stringify({status:'ready'}, null, 2));
            }
        }).catch(error => {
            res.writeHead(500, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:error.message}));
        })
    } else {
        res.writeHead(418, {'Content-Type': 'application/json'});      // I'm a teapot! ;)
        res.end(JSON.stringify({error:'Command is not valid'}));
    }
});


// Sets up get listeners once the config is parsed
function setupListeners(configJSON, WORKSPACE){
    /**
     *  Gets information regarding a specific object
     *  URL: /selectobject?id=objectid&key=[objects|objectgroups|interfaces|users]
     */
    var route = (WORKSPACE == undefined) ? '' : '/' + WORKSPACE.id

    app.get(route + '/selectitem', function(req, res){
        if (req.query.id === undefined || req.query.key === undefined) {
            res.writeHead(400, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:'ID or key missing'}));
        }
        else {
            log.silly('GET /selectitem : ' + JSON.stringify(req.query))
            try {
                var json = parser.selectItem(configJSON,req.query.key,req.query.id)
                res.writeHead(200, {'Content-Type': 'application/json'});
                res.end(JSON.stringify(json, null, 2));
            }
            catch(error){
                res.writeHead(500, {'Content-Type': 'application/json'})
                res.end(JSON.stringify({error:error.message}));
            }
        }
    });

    /**
     *  Gets a paged list of objects for a certain type
     *  URL: /listitems?key=type&per_page=10&page=1
     * 
     *  key can take [objects|objectgroups|routes|interfaces|users|notparsed]
     */
    app.get(route + '/listitems', function(req, res){
        if (req.query.key === undefined) {
            res.writeHead(400, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:'Key missing'}));
        }
        else {
            log.silly('GET /listitems : ' + JSON.stringify(req.query))
            perPage = req.query.per_page || 'ALL'
            page = req.query.page || 1
            try {
                var json = parser.listItems(configJSON, req.query.key, perPage, page)
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'FwCAT-items': json.size.items,
                    'FwCAT-pages': json.size.pages,
                    'FwCAT-page': json.size.page,
                    'FwCAT-pagesize': json.size.pagesize,
                });
                res.end(JSON.stringify({list:json.list}, null, 2));
            }
            catch(error) {
                res.writeHead(500, {'Content-Type': 'application/json'})
                res.end(JSON.stringify({error:error.message}));
            }
        }
    });

    app.get(route + '/listrules/:key', function(req, res){
        if (req.params.key === undefined) {
            res.writeHead(400, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:'Key missing'}));
        }
        else {
            log.silly('GET /listrules/<key> : ' + JSON.stringify(req.query))
            perPage = req.query.per_page || 'ALL'
            page = req.query.page || 1
            if (req.query.match_key !== undefined && req.query.match_value !== undefined){
                var queryMatch = [req.query.match_key,req.query.match_value]
            }
            if (req.query.regex !== undefined) {var isRegEx = true}
            try {
                var json = parser.listRules(configJSON, req.params.key, perPage, page, queryMatch, isRegEx)
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'FwCAT-items': json.size.items,
                    'FwCAT-pages': json.size.pages,
                    'FwCAT-page': json.size.page,
                    'FwCAT-pagesize': json.size.pagesize,
                });
                res.end(JSON.stringify({list:json.list}, null, 2));
            }
            catch(error) {
                res.writeHead(500, {'Content-Type': 'application/json'})
                res.end(JSON.stringify({error:error.message}));
            }
        }
    });

    app.get(route + '/hostdata', function(req, res){
        log.silly('GET /hostdata')
        if (!('host' in configJSON) || !('fwType' in configJSON.host)){
            res.writeHead(500, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:'The parser was unable to retrieve host data'}));
        }
        else {
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({host:configJSON.host}, null, 2));
        }
    });
}

app.get('/workspaces', function(req,res){
    log.silly('GET /workspaces')
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify(workspaces, null, 2));
})

function createWorkspace(WORKSPACES){
    while (true){
        var rnd = [...Array(15)].map(i=>(~~(Math.random()*36)).toString(36)).join('')
        if (WORKSPACES.filter(o => o.id == rnd).length == 0) break
    }
    WORKSPACES.push({id:rnd})
    return WORKSPACES
}


// port = 3000;
// server = app.listen(port);
// console.log('Listening at http://localhost:' + port)
// module.exports = server

var server = app.listen(3000, function () {
    var port = server.address().port;
    log.silly('API listening at http://localhost:%s', port);
});

module.exports = server;
