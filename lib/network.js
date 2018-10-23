/**
 * @overview Various utilities for manipulating networking data
 * @author Jorge Valentini <jdval@protonmail.com>
 * @license GPL-3.0-or-later
 * @module FWC-Network
 * @version 0.5
 */

module.exports = {
    mask2cidr: mask2cidr,
    ip2cidr: ip2cidr,
    isIPv4: isIPv4,
    isIPv6: isIPv6,
}

/**
 * Converts a subnet mask given in decimal notation, to the prefix length used for CIDR notation.
 * 
 * @param {string} mask - The subnet mask given in decimal notation and divided in octets.
 * @returns {number} Returns the prefix length: the amount of bits set to 1 in the subnet mask.
 * 
 * @example <caption>Class C mask conversion:</caption>
 * // returns 24
 * mask2cidr('255.255.255.0')
 */
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


/**
 * Checks if a string is a valid IPv4 address represented in decimal notation
 * 
 * @param {string} ip - String to test if it is a valid IPv4 address.
 * @returns {boolean} True if string is a valid IP address, False otherwise.
 */
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


/**
 * Checks if a string is a valid IPv6 address
 * 
 * @param {string} ip - String to test if it is a valid IPv6 address.
 * @returns {boolean} True if string is a valid IP address, False otherwise.
 */
function isIPv6(ip){
    if (typeof ip !== 'string') {return false}
    reg = /^((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*::((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4}))*|((?:[0-9A-Fa-f]{1,4}))((?::[0-9A-Fa-f]{1,4})){7}((\|[0-9]{0,2}))$/
    return reg.test(ip) // Test if this works for real in every case...
}


/**
 * Converts an IP and mask given in decimal notation to CIDR notation. Optionally it gives the network address
 * 
 * @param {string} ip - IP address given in decimal notation.
 * @param {string} mask - Subnet mask given in decimal notation.
 * @param {boolean} [convertToSubnet] - Return the network address instead of the original host address.
 * @returns {string} True if string is a valid IP address, False otherwise.
 * 
 * @example <caption>Host conversion:</caption>
 * // returns '10.0.0.1/24'
 * ip2cidr('10.0.0.1','255.255.255.0')
 * 
 * @example <caption>Host conversion to network:</caption>
 * //returns '172.16.2.0/23'
 * ip2cidr('172.16.3.25','255.255.254.0',true)
 */
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