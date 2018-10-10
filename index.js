const parser = require(__dirname + '/parser.js')
const log = require('electron-log')
const http = require('http');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();

// cfg = parser.parseFirewall('/src/ciscotest.cfg')
// cfg.then(data =>{console.log(JSON.stringify(data, null, 2))}) //  Write the .catch()

const cfgFile = "./src/cisco-internet.cfg";

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, 'static')));

app.get('/', function(req, res){
    console.log('GET /')
    //var html = '<html><body><form method="post" action="http://localhost:3000">Name: <input type="text" name="name" /><input type="submit" value="Submit" /></form></body>';
    var html = fs.readFileSync('index.html');
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(html);
});

app.post('/', function(req, res){
    console.log('POST /');
    console.dir(req.body);
    if (req.body.cmd == 'parseTest'){
        cfg = parser.parseFirewall(cfgFile)
        cfg.then(config =>{
            res.writeHead(200, {'Content-Type': 'text/json'});
            res.end(JSON.stringify(config, null, 2));
        })
    } else {
        res.writeHead(200, {'Content-Type': 'text/json'});
        res.end(JSON.stringify({error:'Command is not valid'}));
    }
});

port = 3000;
app.listen(port);
console.log('Listening at http://localhost:' + port)