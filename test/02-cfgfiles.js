const parser = require('../parser.js');
const assert = require('assert');

describe('Parser: Detect firewall type (for parsing syntax)', () => {
    var configCisco1 = __dirname + '/cfg-cisco-asa98-01.cfg'
    var configCisco2 = __dirname + '/cfg-cisco-asa87-01.cfg'
    var configUnknown1 = __dirname + '/cfg-unknown-file-01.cfg'
    var configUnknown2 = __dirname + '/cfg-unknown-file-02.cfg'

    it('Returns parsing syntax of different firewall models', () => {
        parser.detectType(configCisco1).then(FWTYPE => {
            assert.equal(FWTYPE,'cisco-asa')
        })
    })

    it('Throws an error if the detected firewall is unsupported', () => {
        parser.detectType(configCisco2).then(FWTYPE => {
            throw new Error('It was not expected to resolve...')
        }).catch((err) => {
            assert.equal(err,'Unsupported Cisco ASA version')
        })
    })

    it('Throws an error if the firewall type cannot be detected', () => {
        parser.detectType(configUnknown1).then(FWTYPE => {
            throw new Error('It was not expected to resolve...')
        }).catch((err) => {
            assert.equal(err,'Could not detect model in the first 50 lines')
        })

        parser.detectType(configUnknown2).then(FWTYPE => {
            throw new Error('It was not expected to resolve...')
        }).catch((err) => {
            assert.equal(err,'Finished reading file ' + configUnknown2 + ' and no type was detected')
        })
    })
})

describe('Parse configuration file: Cisco ASA 9.8', () => {
    var configFile = __dirname + '/cfg-cisco-asa98-01.cfg'
    it('Understands host parameters', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.host.hostname,'ASATEST')
            assert.equal(data.host.domainname,'cisco.local')
            assert.equal(data.host.serial,'AAA123456')
            assert.equal(data.host.model,'ASA5525')
        })
    })

    it('Understands interfaces', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.interfaces.length, 3)
            assert.equal(data.interfaces[0].ip, '10.0.0.1/26')
            assert.equal(data.interfaces[0]['securitylevel'], '100')
        })
    })

    it('Understands objects and object groups', () => {
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

    it('Understands NAT rules', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.rules.nat.length, 1)
            assert.equal(data.rules.nat[0].srcInterface, 'ETH0')
            assert.equal(data.rules.nat[0].dstInterface, 'ETH1')
        })
    })

    it('Understands DNS servers', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.interfaces[1].dns[0], '10.0.1.1')
            assert.equal(data.interfaces[1].dns[1], '10.0.1.2')
            assert.equal(data.interfaces[1].dns.length, 2)
            assert.equal(data.interfaces[1].dnslookup, true)
            assert.equal(data.interfaces[2].dns[0], '8.8.8.8')
        })
    })

    it('Understands route table', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.routes[0].interface, 'ETH1')
            assert.equal(data.routes[0].destination, 'default')
            assert.equal(data.routes[0].via, '10.0.0.254')
            assert.equal(data.routes[0].metric, '1')

            assert.equal(data.routes[1].interface, 'ETH0')
            assert.equal(data.routes[1].destination, '10.0.0.0/8')
            assert.equal(data.routes[1].via, '10.254.254.254')
            assert.equal(data.routes[1].metric, '10')
        })
    })

    it('Understands system users', () => {
        parser.parseFirewall(configFile).then(data =>{
            assert.equal(data.users[0].id, 'admin')
            assert.equal(data.users[0].hash, 'hash3dp4ss')
            assert.equal(data.users[0].encrypted, true)
            assert.equal(data.users[0].privilege, '15')
        })
    })
})