/**
 * @overview Web API for firewal parsing.
 * @author Jorge Valentini <jdval@protonmail.com>
 * @license GPL-3.0-or-later
 * @version 0.1
 */

const parser = require(__dirname + '/parser.js')
const log = require('electron-log')
const express = require('express');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// app.use(express.static(path.join(__dirname, 'static')));

// Waits for POST request with the config file path --> data: {cmd:"parseCfg", cfgFile:"/path/to/file.cfg"}
app.post('/', function(req, res){
    log.silly('POST /');
    if (req.body.cmd == 'parseCfg'){
        cfg = parser.parseFirewall(req.body.cfgFile)
        cfg.then(config =>{
            res.writeHead(200, {'Content-Type': 'application/json'});
            setupListeners(config)
            res.end(JSON.stringify({status:'ready'}, null, 2));
        })
    } else {
        res.writeHead(418, {'Content-Type': 'application/json'});      // I'm a teapot! ;)
        res.end(JSON.stringify({error:'Command is not valid'}));
    }
});


// Sets up get listeners once the config is parsed
function setupListeners(configJSON){
    /**
     *  Gets information regarding a specific object
     *  URL: /selectobject?id=objectid&key=[objects|objectgroups|interfaces|users]
     */
    app.get('/selectitem', function(req, res){
        if (req.query.id === undefined || req.query.key === undefined) {
            res.writeHead(400, {'Content-Type': 'application/json'})
            res.end(JSON.stringify({error:'ID or key missing'}));
        }
        else {
            log.silly('GET /object : ' + JSON.stringify(req.query))
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
    app.get('/listitems', function(req, res){
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

    app.get('/listrules/:key', function(req, res){
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

    app.get('/hostdata', function(req, res){
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

    app.get('*', function(req,res){
        res.writeHead(404, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error:'Ooops... nothing here'}))
    })
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