const parser = require(__dirname + '/parser.js')
const log = require('electron-log')
const http = require('http');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();

// cfg = parser.parseFirewall('/src/cisco-matta-internet.cfg')
// cfg = parser.parseFirewall('/src/ciscotest.cfg')
// cfg.then(data =>{console.log(JSON.stringify(data, null, 2))}) //  Write the .catch()

// server = http.createServer((req, res) => {
//     // console.dir(req.param);

//     if (req.method == 'POST') {
//         console.log("POST");
//         var body = '';
//         req.on('data', function(data) {
//             if (data.cmd == 'parseTest'){
//                 cfg = parser.parseFirewall('/src/cisco-matta-internet.cfg')
//                 cfg.then(config =>{JSON.stringify(config, null, 2)})
//             }
//             console.log("Received: " + data);
//         });
//         req.on('end', function() {
//             console.log("Request Finished: ");
//         });
//         res.writeHead(200, {'Content-Type': 'text/html'});
//         res.end('POST received');
//     }
//     else
//     {
//         console.log("GET");
//         //var html = '<html><body><form method="post" action="http://localhost:3000">Name: <input type="text" name="name" /><input type="submit" value="Submit" /></form></body>';
//         var html = fs.readFileSync('index.html');
//         res.writeHead(200, {'Content-Type': 'text/html'});
//         res.end(html);
//     }
// });

// port = 3000;
// host = '127.0.0.1';
// server.listen(port, host);
// console.log('Listening at http://' + host + ':' + port);

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
        cfg = parser.parseFirewall('/src/cisco-matta-internet.cfg')
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