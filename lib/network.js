module.exports = {
    mask2cidr: mask2cidr,
    isIPv4: isIPv4,
    isIPv6: isIPv6,
    ip2cidr: ip2cidr,
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

function ip2cidr(ip,mask,convertToSubnet){
    convertToSubnet = convertToSubnet || false
    if (isIPv4(ip)){
        if (convertToSubnet){
            cidr = mask2cidr(mask)
            binIP = ''
            for (octet of ip.split('.')) {
                binOctet = (octet >>> 0).toString(2)
                binIP += '0'.repeat(8-binOctet.length) + binOctet
            }
            if (binIP.length !== 32) {throw new Error('ERROR 1: Error in calculations')}
            subnetIP = binIP.substring(0,cidr) + '0'.repeat(32-cidr) // Host bits to 0
            octet1 = parseInt(subnetIP.substring(0,8),2)
            octet2 = parseInt(subnetIP.substring(8,16),2)
            octet3 = parseInt(subnetIP.substring(16,24),2)
            octet4 = parseInt(subnetIP.substring(24,32),2)
            return octet1 + '.' + octet2 + '.' + octet3 + '.' + octet4 + '/' + cidr
        }
        else {
            return ip + '/' + mask2cidr(mask)
        }
    } 
    else {
        throw new Error('Invalid parameters received --> IP: ' + ip + ' Mask: ' + mask);
    }
}