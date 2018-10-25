const parser = require('../parser.js');
const cisco = require('../lib/parser-cisco.js')
const network = require('../lib/network.js')
const assert = require('assert');

describe('Network Module: isIPv4 function',()=>{
    it('Returns false when IP is not a string', () =>{
        assert.equal(network.isIPv4(10),false)
    })
    it('Returns false when IP is invalid', () =>{
        assert.equal(network.isIPv4('10.0.0.1000'),false)
        assert.equal(network.isIPv4('10.0.0.x'),false)
        assert.equal(network.isIPv4('10.0.256.0'),false)
        assert.equal(network.isIPv4('10.-1.0.1'),false)
        assert.equal(network.isIPv4('58'),false)
    })
    it('Returns true when IP is a valid IPv4', () =>{
        assert.equal(network.isIPv4(10),false)
    })
})

describe('Network Module: ip2cidr function',()=>{
    it('Returns IP/prefix given network IP and mask', () =>{
        assert.equal(network.ip2cidr('10.0.0.0','255.0.0.0'),'10.0.0.0/8')
    })

    it('Throws error when IP or Mask is invalid', () =>{
        assert.throws(function(){network.ip2cidr(0,'255.255.255.0')},Error)
        assert.throws(function(){network.ip2cidr('10.0.0.0','255.255.255')},Error)
        assert.throws(function(){network.ip2cidr('10.0.0.0','255.255.0.255')},Error)
    })

    it('Converts to network address when specified', () =>{
        assert.equal(network.ip2cidr('10.1.23.5','255.0.0.0',true),'10.0.0.0/8')
        assert.equal(network.ip2cidr('192.168.1.143','255.255.255.128',true),'192.168.1.128/25')
        assert.equal(network.ip2cidr('172.16.3.100','255.255.254.0',true),'172.16.2.0/23')
        assert.equal(network.ip2cidr('172.16.3.100','255.255.254.0'),'172.16.3.100/23')
    })
})

describe('Cisco Module: parseAccessList function', function(){
    it('Parses standard ACEs', function(){
        var test = 'access-list ACLNAME standard permit 192.168.0.0 255.255.0.0'
        var ace = cisco.parseAccessList(test,1)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'standard')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.dstAddress, '192.168.0.0/16')
    })

    it('Parses extended ACEs based on address', function(){
        var test = 'access-list ACLNAME extended deny ip any4 object-group DST_OBJECT'
        var ace = cisco.parseAccessList(test,1)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'deny')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, 'object-group DST_OBJECT')

        var test = 'access-list ACLNAME extended deny ip any4 8.8.8.0 255.255.254.0'
        var ace = cisco.parseAccessList(test,1,'access-list ACLNAME remark This is a comment')
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'deny')
        assert.equal(ace.protocol, 'ip')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, '8.8.8.0/23')
        assert.equal(ace.comment, 'This is a comment')
    })

    it('Parses extended ACEs based on address and ports', function(){
        var test = 'access-list ACLNAME extended permit object-group SRV_OBJECT any4 object-group DST_OBJECT'
        var ace = cisco.parseAccessList(test,1)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'object-group SRV_OBJECT')
        assert.equal(ace.srcAddress, 'any4')
        assert.equal(ace.dstAddress, 'object-group DST_OBJECT')

        var test = 'access-list ACLNAME extended permit tcp host 10.0.0.1 eq 12345 any4 object-group DST_OBJECT'
        var ace = cisco.parseAccessList(test,1)
        assert.equal(ace.line, test)
        assert.equal(ace.acl, 'ACLNAME')
        assert.equal(ace.type, 'extended')
        assert.equal(ace.action, 'permit')
        assert.equal(ace.protocol, 'tcp')
        assert.equal(ace.srcAddress, '10.0.0.1')
        assert.equal(ace.srcPort, '12345')
        assert.equal(ace.dstAddress, 'any4')
        assert.equal(ace.dstPort, 'object-group DST_OBJECT')
    })

})

describe('Cisco Module: typedParseLine function',() => {
    it('Parses network and service objects', () => {
        var result = parser.parseLine('cisco-asa', ' host 10.0.0.1', ['object network OBJHOST'])
        assert.equal(result.sk,'OBJHOST-network')
        assert.equal(result.v.syntax,'host')
        assert.equal(result.v.address,'10.0.0.1')

        var result = parser.parseLine('cisco-asa', ' subnet 192.168.0.0 255.255.255.0', ['object network OBJSUBNET'])
        assert.equal(result.sk,'OBJSUBNET-network')
        assert.equal(result.v.syntax,'subnet')
        assert.equal(result.v.address,'192.168.0.0/24')

        var result = parser.parseLine('cisco-asa', ' fqdn v4 www.example.com', ['object network OBJHOST'])
        assert.equal(result.sk,'OBJHOST-network')
        assert.equal(result.v.syntax,'fqdn')
        assert.equal(result.v.address,'www.example.com')

        var result = parser.parseLine('cisco-asa', ' range 192.168.254.30 192.168.254.35', ['object network OBJHOST'])
        assert.equal(result.sk,'OBJHOST-network')
        assert.equal(result.v.syntax,'range')
        assert.equal(result.v.address,'192.168.254.30-192.168.254.35')

        var result = parser.parseLine('cisco-asa', ' service tcp source eq 9535 destination neq 9535', ['object service OBJSRV'])
        assert.equal(result.sk,'OBJSRV-service')
        assert.equal(result.v.protocol,'tcp')
        assert.equal(result.v.source,'9535')
        assert.equal(result.v.destination,'!9535')

        var result = parser.parseLine('cisco-asa', ' service sctp destination range 21 22', ['object service OBJSRV'])
        assert.equal(result.sk,'OBJSRV-service')
        assert.equal(result.v.protocol,'sctp')
        assert.equal(result.v.destination,'21-22')

        var result = parser.parseLine('cisco-asa', ' service icmp', ['object service OBJSRV'])
        assert.equal(result.sk,'OBJSRV-service')
        assert.equal(result.v.protocol,'icmp')

        var result = parser.parseLine('cisco-asa', ' description This is a test for object parsing', ['object service OBJSRV'])
        assert.equal(result.sk,'OBJSRV-service')
        assert.equal(result.v.description,'This is a test for object parsing')

        var result = parser.parseLine('cisco-asa', ' host 10.0.0.1', ['object network OBJ-10.0.0.1_ex_192.168.0.1_int'])
        assert.equal(result.sk,'OBJ-10.0.0.1_ex_192.168.0.1_int-network')
        assert.equal(result.v.syntax,'host')
        assert.equal(result.v.address,'10.0.0.1')

        var result = parser.parseLine('cisco-asa', 'object network obj-10.0.0.1_ex_192.168.0.1_int', [])
        assert.equal(result.h,0)
        assert.equal(result.k,'objects')
        assert.equal(result.sk,'parent')
        assert.equal(result.v.id,'obj-10.0.0.1_ex_192.168.0.1_int')
        assert.equal(result.v.type,'network')
    })

    it('Parses network object groups', () => {
        var result = parser.parseLine('cisco-asa', ' network-object object OBJ', ['object-group network GROUP'])
        assert.equal(result.sk, 'GROUP-network')
        assert.equal(result.v.syntax, 'object')
        assert.equal(result.v.id, 'OBJ')

        var result = parser.parseLine('cisco-asa', ' network-object 10.0.0.0 255.0.0.0', ['object-group network GROUP'])
        assert.equal(result.sk, 'GROUP-network')
        assert.equal(result.v.syntax, 'subnet')
        assert.equal(result.v.address, '10.0.0.0/8')
    })

    it('Parses service object groups', () => {
        var result = parser.parseLine('cisco-asa', ' service-object tcp destination eq 123', ['object-group service GROUP'])
        assert.equal(result.v.protocol, 'tcp')
        assert.equal(result.v.destination, '123')
        assert.equal(result.sk, 'GROUP-service')
        assert.equal(result.v.syntax, 'ports')

        var result = parser.parseLine('cisco-asa', ' description Service group description', ['object-group service GROUP'])
        assert.equal(result.sk, 'GROUP-service')
        assert.equal(result.v.syntax, 'description')
        assert.equal(result.v.description, 'Service group description')
    })

    it('Parses NAT rules', () => {
        var result = cisco.parseNAT('nat (New-Inside,New-Outside) source static 192.168.0.1 8.8.0.1', 0)
        assert.equal(result.srcInterface,'New-Inside')
        assert.equal(result.dstInterface,'New-Outside')
    })
})

describe('Parser: listItems function', () => {
    var configJSON = {
        routes:[
            {id:'test1'},{id:'test2'},{id:'test3'},{id:'test4'},{id:'test5'},
            {id:'test6'},{id:'test7'},{id:'test8'},{id:'test9'},{id:'test10'}
        ]
    }

    it('Separates in pages the listed results', () => {
        var list = parser.listItems(configJSON,'routes',4)
        assert.equal(list.size.pages,3)
        assert.equal(list.size.items,10)
        assert.equal(list.size.page,1)
        assert.equal(list.size.pagesize,4)
        assert.equal(list.list.length,4)

        list = parser.listItems(configJSON,'routes',4,3)
        assert.equal(list.list.length,2)
        assert.equal(list.list[1].id,'test10')

        list = parser.listItems(configJSON,'routes')
        assert.equal(list.size.pages,1)
        assert.equal(list.size.items,10)
        assert.equal(list.size.page,1)
        assert.equal(list.size.pagesize,10)
        assert.equal(list.list.length,10)
        assert.equal(list.list[9].id,'test10')
    })

    it('Sets "ALL" as page size if requested is bigger than length',() => {
        list = parser.listItems(configJSON,'routes',15)
        assert.equal(list.size.pagesize,10)
        assert.equal(list.size.pages,1)
        assert.equal(list.list[5].id,'test6')
    })

    it('Returns last page if page is after the last',() => {
        list = parser.listItems(configJSON,'routes',4,4)
        assert.equal(list.size.page,3)
        assert.equal(list.size.pages,3)
        assert.equal(list.list[0].id,'test9')
    })

    it('Throws error string if the item key requested is invalid', () => {
        assert.throws(function(){parser.listItems(configJSON,'invalidkey',3,5)},Error)
    })
})

describe('Parser: selectItem function', () => {
    var configJSON = {
        interfaces:[
            {id:'Gigabit1', ip: "10.0.0.1/24"},
            {id:'Management0', ip: "10.0.0.2/24"},
            {id:'Portchannel0.1', ip: "10.0.0.3/24"},
            {id:'Management0', ip: "10.0.0.4/24"}
        ]
    }
    it('Returns details on a given item ID and type of object', () => {
        item = parser.selectItem(configJSON,'interfaces','Portchannel0.1')
        assert.equal(item.item.ip,"10.0.0.3/24")
    })

    it('Returns a warning if the item ID is not unique', () => {
        item = parser.selectItem(configJSON,'interfaces','Management0')
        assert.equal(item.item.ip,"10.0.0.2/24")
        assert.equal(item.warning,'Multiple items selected')
    })

    it('Throws error string if the item key requested is invalid', () => {
        assert.throws(function(){parser.selectItem(configJSON,'invalidkey','test')},Error)
    })
})