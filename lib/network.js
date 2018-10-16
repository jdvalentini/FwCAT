module.exports = {
    mask2cidr: mask2cidr,
    isIPv4: isIPv4,
    isIPv6: isIPv6,
}

function mask2cidr(mask){
    var cidr = ''
    for (m of mask.split('.')) {
        if (parseInt(m)>255) {throw 'ERROR 1: Invalid Netmask'}
        if (parseInt(m)>0 && parseInt(m)<128) {throw 'ERROR 2: Invalid Netmask'}
        cidr+=(m >>> 0).toString(2)
    }
    // Condition to check for validity of the netmask
    if (/01/.test(cidr)) {throw 'ERROR 3: Invalid Netmask ' + mask}
    return cidr.split('1').length-1
}

function isIPv4(ip) {
    if (typeof ip !== 'string') {return false}
    if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(ip)) {
        for (octet of ip.split('.')) {
            if (parseInt(octet)>255 || parseInt(octet)<0) {return false}
        }
        return true
    }
    return false
} 

function isIPv6(ip){
    if (typeof ip !== 'string') {return false}
    reg = /^((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}((\|[0-9]{0,2}))$/
    return reg.test(ip) // Test if this works for real in every case...
}