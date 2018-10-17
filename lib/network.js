module.exports = {
    mask2cidr: mask2cidr,
    isIPv4: isIPv4,
    isIPv6: isIPv6,
    subnet2cidr: subnet2cidr,
}

function mask2cidr(mask){
    var cidr = ''
    if (!(/\d+\.\d+\.\d+\.\d+/.test(mask))) {throw new Error('ERROR 4: Invalid Netmask')}
    for (m of mask.split('.')) {
        if (parseInt(m)>255) {throw new Error('ERROR 1: Invalid Netmask')}
        if (parseInt(m)>0 && parseInt(m)<128) {throw new Error('ERROR 2: Invalid Netmask')}
        cidr+=(m >>> 0).toString(2)
    }
    if (/01/.test(cidr)) {throw new Error('ERROR 3: Invalid Netmask ' + mask)}
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

function subnet2cidr(ip,mask){
    if (isIPv4(ip)){
        return ip + '/' + mask2cidr(mask)
    } 
    else {
        throw new Error('Invalid parameters received --> IP: ' + ip + ' Mask: ' + mask);
    }
}