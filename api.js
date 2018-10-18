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
    console.log('POST /');
    console.dir(req.body);
    if (req.body.cmd == 'parseCfg'){
        cfg = parser.parseFirewall(req.body.cfgFile)
        cfg.then(config =>{
            res.writeHead(200, {'Content-Type': 'text/json'});
            setupListeners(config)
            res.end(JSON.stringify({status:'ready'}, null, 2) + '\r\n');
        })
    } else {
        res.writeHead(418, {'Content-Type': 'text/json'});      // I'm a teapot! ;)
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
            res.writeHead(400, {'Content-Type': 'text/json'})
            res.end(JSON.stringify({error:'ID missing'}));
        }
        else {
            log.silly('GET /object : ' + JSON.stringify(req.query))
            try {
                var json = parser.selectItem(configJSON,req.query.key,req.query.id)
                res.writeHead(200, {'Content-Type': 'text/json'});
                res.end(JSON.stringify(json, null, 2) + '\r\n');
            }
            catch(error){
                res.writeHead(500, {'Content-Type': 'text/json'})
                res.end(JSON.stringify({error:error.message}) + '\r\n');
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
            res.writeHead(400, {'Content-Type': 'text/json'})
            res.end(JSON.stringify({error:'Key missing'}));
        }
        else {
            log.silly('GET /listitems : ' + JSON.stringify(req.query))
            perPage = req.query.per_page || 'ALL'
            page = req.query.page || 1
            try {
                var json = parser.listItems(configJSON, req.query.key, perPage, page)
                res.writeHead(200, {'Content-Type': 'text/json'});
                res.end(JSON.stringify(json, null, 2) + '\r\n');
            }
            catch(error) {
                res.writeHead(500, {'Content-Type': 'text/json'})
                res.end(JSON.stringify({error:error.message}) + '\r\n');
            }
        }
    });
}


port = 3000;
app.listen(port);
console.log('Listening at http://localhost:' + port)