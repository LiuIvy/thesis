const topology = require('./topology.js').Topology;

function parse ( line ) {
    lineSplit = line.trim().split(':');
    console.log(lineSplit);
}


module.exports.parse = parse;