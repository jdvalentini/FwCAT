const parser = require('../parser.js');
const assert = require('assert');

describe('Parse configuration file: Cisco ASA 9.8', ()=> {
    var configFile = __dirname + '/cfg-cisco-asa98-01.cfg'
    it('Understands host parameters', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.host.hostname,'ASATEST')
            assert.equal(data.host.domain,'cisco.local')
        })
    })

    it('Understands objects', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.objects.length,2)
            assert.equal(parser.selectObject(data,'OBJNETWORK')[0].address, '192.168.0.1')
            assert.equal(parser.selectObjectGroup(data,'SERVICEGROUP')[0].objects[2].port, '>1024')
            assert.equal(parser.selectObjectGroup(data,'OBJGROUP')[0].objects.length, 2)
        })
    })

    it('Understands access lists', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.rules.filter.length, 1)
            assert.equal(data.rules.filter[0].comment, 'ACL Comment')
            assert.equal(data.rules.filter[0].protocol, 'object-group PROTOGROUP')
        })
    })
})