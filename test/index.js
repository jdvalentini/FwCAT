var parser = require('../parser.js');
var assert = require('assert');

describe('isIPv4 function',()=>{
    it('Returns false when IP is not a string', () =>{
        assert.equal(parser.isIPv4(10),false)
    })
    it('Returns false when IP is invalid', () =>{
        assert.equal(parser.isIPv4('10.0.0.1000'),false)
        assert.equal(parser.isIPv4('10.0.0.x'),false)
        assert.equal(parser.isIPv4('10.0.256.0'),false)
        assert.equal(parser.isIPv4('10.-1.0.1'),false)
        assert.equal(parser.isIPv4('58'),false)
    })
    it('Returns true when IP is a valid IPv4', () =>{
        assert.equal(parser.isIPv4(10),false)
    })
})

describe('ciscoParseAccessList function', function(){
    it('Parses standard ACEs', function(){
        var test = 'access-list ACLNAME standard permit 192.168.0.0 255.255.0.0'
        var ace = parser.ciscoParseAccessList(test)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'standard')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.dstAddress, '192.168.0.0/16')
    })

    it('Parses extended ACEs based on address', function(){
        var test = 'access-list ACLNAME extended deny ip any4 object-group DST_OBJECT'
        var ace = parser.ciscoParseAccessList(test)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'deny')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, 'object-group DST_OBJECT')

        var test = 'access-list ACLNAME extended deny ip any4 8.8.8.0 255.255.254.0'
        var ace = parser.ciscoParseAccessList(test)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'deny')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, '8.8.8.0/23')
    })

    it('Parses extended ACEs based on address and ports', function(){
        var test = 'access-list ACLNAME extended permit object-group SRV_OBJECT any4 object-group DST_OBJECT'
        var ace = parser.ciscoParseAccessList(test)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'object-group SRV_OBJECT')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, 'object-group DST_OBJECT')

        var test = 'access-list ACLNAME extended permit tcp host 10.0.0.1 eq 12345 any4 object-group DST_OBJECT'
        var ace = parser.ciscoParseAccessList(test)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'tcp')
        assert.equal(ace.srcAddress, '10.0.0.1')
        assert.equal(ace.srcPort, 'eq 12345')
        assert.equal(ace.dstAddress, 'any4')
        assert.equal(ace.dstPort, 'object-group DST_OBJECT')
    })
})