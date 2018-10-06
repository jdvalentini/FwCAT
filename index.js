const parser = require(__dirname + '/parser.js')
const log = require('electron-log')


cfg = parser.parseFirewall('/src/cisco-matta-internet.cfg')
// cfg = parser.parseFirewall('/src/ciscotest.cfg')
cfg.then(data =>{console.log(JSON.stringify(data, null, 2))}) //  Write the .catch()