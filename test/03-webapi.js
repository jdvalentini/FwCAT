const api = require('../api.js')

const request = require('supertest');
const assert = require('assert');

describe('WEB API: config file parsing upon proper requests', function () {
    var server = require('../api.js');

    it('Returns 418 if POST /parse command is not understood', function testSlash(done) {
        request(server)
        .post('/parse')
        .expect(418, done);
    });

    it('Returns 200 if POST /parse command is parseCfg and gives a file', function testSlash(done) {
        request(server)
        .post('/parse')
        .type('form')
        .send({cmd:"parseCfg", cfgFile: __dirname + "/cfg-cisco-asa98-01.cfg"})
        .expect(200)
        .expect("Content-type",/json/)
        .expect(JSON.stringify({status:'ready'},null,2))
        .end(function (err, res) {
            if (err) done(err)
            else done();
        });
    });

    it('Returns JSON list if GET /listitems?key=<itemKey> is requested', function() {
        return request(server)
        .get('/listitems?key=routes')
        .set('Accept','application/json')
        .expect("Content-type",/json/)
        .expect("FwCAT-items",'2')
        .expect("FwCAT-pages",'1')
        .expect("FwCAT-page",'1')
        .expect("FwCAT-pagesize",'2')
        .expect(200)
        .expect((res) => {
            if (!('list' in res.body)) throw new Error('missing "list" key')
            if (res.body.list[0].interface !== 'ETH1') throw new Error('Expected ETH1 and found ' + res.body.list[0].interface)
            if (res.body.list[1].metric !== '10') throw new Error('Expected 10 and found ' + res.body.list[1].metric)
        })
    });

    it('Returns JSON item if GET /selectitem?key=<itemKey>&id=<itemID> is requested', function() {
        return request(server)
        .get('/selectitem?key=objects&id=HTTP')
        .set('Accept','application/json')
        .expect("Content-type",/json/)
        .expect(200)
        .expect((res) => {
            if (!('item' in res.body)) throw new Error('missing object HTTP details')
            if (res.body.item.type !== 'service') throw new Error('Expected "service" and found ' + res.body.item.type)
            if (res.body.item.protocol !== 'tcp') throw new Error('Expected "tcp" and found ' + res.body.item.protocol)
        })
    });

    it('Returns JSON host details if GET /hostdata is requested', function() {
        return request(server)
        .get('/hostdata')
        .set('Accept','application/json')
        .expect("Content-type",/json/)
        .expect(200)
        .expect((res) => {
            if (!('host' in res.body)) throw new Error('missing host details')
            if (res.body.host.hostname !== 'ASATEST') throw new Error('Expected "ASATEST" and found ' + res.body.host.hostname)
            if (res.body.host.domainname !== 'cisco.local') throw new Error('Expected "cisco.local" and found ' + res.body.host.domainname)
            if (res.body.host.serial !== 'AAA123456') throw new Error('Expected "AAA123456" and found ' + res.body.host.serial)
            if (res.body.host.model !== 'ASA5525') throw new Error('Expected "ASA5525" and found ' + res.body.host.model)
        })
    });

    it('Returns 500 if the parser cannot process the request', function() {
        return request(server)
        .get('/selectitem?key=invalidkey&id=HTTP')
        .set('Accept','application/json')
        .expect("Content-type",/json/)
        .expect(500)
    });

    it('Returns 400 if the request is malformed (For instance missing key)', function() {
        return request(server)
        .get('/selectitem')
        .set('Accept','application/json')
        .expect("Content-type",/json/)
        .expect(400)
    });

    it('Returns 404 if the requested route is inexistent', function() {
        return request(server)
        .get('/inexistent')
        .expect(404)
    });
    
    server.close();
});

describe('WEB API: Workspace separation', function () {
    var server = require('../api.js');

    it('Handles auto-generated workspaces', function() {
        request(server)
        .post('/parse')
        .type('form')
        .send({cmd:"parseCfg", cfgFile: __dirname + "/cfg-cisco-asa98-01.cfg", workspace:true})
        .expect(200)
        .expect("Content-type",/json/)
        .expect((res) => {
            if (!('workspace' in res.body)) throw new Error('Missing workspace data')
            if (res.body.workspace.configFile !== __dirname + "/cfg-cisco-asa98-01.cfg") throw new Error('Errors in workspace response')
        })
        .end(function (err, res) {
            if (err) done(err)
            else {
                workspace.push(res.body.workspace)
                done();
            }
        });        
    });
});
