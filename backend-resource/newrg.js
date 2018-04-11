const fs = require('fs');
const path = require('path');
const util = require('util');
const topology = require('./topology.js').Topology;
const argv = process.argv.slice(2);
const getopt = require('node-getopt').create([
    ['h', 'help'    , 'Display this help.'],
    ['r', '='		, 'For Random mode.'],
    ['n', '='		, 'For Random mode.'],
    ['p', '='       , 'For Informed mode.']
    ]).bindHelp();


opt = getopt.parse(argv);
console.info(opt);

if ( Object.keys(argv).length == 0 ) {
    console.log(`Process execute in default(Random) mode with 3 interfaces.`);
    // execute random mode
}
else if ( Object.keys(argv).length > 0 ) {
    if ( opt['options']['r'] && opt['options']['p'] ) {
        console.log(`\x1b[1m[err] Option "r" and "p" can't exist at same time.\x1b[0m`)
        process.exit(1);
    }
    else {
        if ( opt['options']['r'] ) {
        	if ( !opt['options']['n'] ) {
        		console.log(`\x1b[1m[err] It's necessary to provide numbers of networks with option "-n".\x1b[0m`)
    			process.exit(1);
        	}
        	random_topology_generator(opt['options']['r'], opt['options']['n']);
            // execute random mode
        }
        else if ( opt['options']['p'] ) {
            if ( !fs.existsSync(opt['options']['p']) ) {
                console.log(`\x1b[1m[err] The follow argument isn't a path, or file isn't exist.\x1b[0m`);
                console.log(`Path: \x1b[91m` + opt['options']['p'] + `\x1b[0m`);
                process.exit(1);
            }
            console.log(`Process execute in Informed mode with file path: ` + opt['options']['p']);
            
        }
    }
}
else if ( Object.keys(argv).length < 0 ) {
    console.log(`\x1b[1m[err] Some error is occured, and numbers of argument is less than 0.\x1b[0m`)
    process.exit(1);
}


function random_topology_generator ( rtNum, nwNum ) {
	let topoScript = [], line;

	let topoObject = new topology(),
		fw1 = topoObject.addFirewall('fw1'),
		fw2 = topoObject.addFirewall('fw2'),
		fw3 = topoObject.addFirewall('fw3'),
		nw1 = topoObject.addNetwork('nw1', '1.0.0.0/16'),
		nw2 = topoObject.addNetwork('nw2', '2.0.0.0/16');
	topoObject.addLink(nw1, fw1);
	topoObject.addLink(fw1, fw2);
	topoObject.addLink(fw1, fw3);
	topoObject.addLink(fw2, fw3);
	topoObject.addLink(fw2, nw2);

	topoObject.showTopology();
	topoObject.showPath();
	

}

// function topology_parser (  ) {}


function random ( low, high ) {
    return Math.floor(Math.random() * (high - low + 1) + low);
}