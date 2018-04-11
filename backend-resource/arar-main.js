const util = require('util');
const deepcopy = require('deepcopy');
const myutils = require('./my-utils');

let rsvFirst, baseSrc, baseDest;
let Queue, QueueNumber, QueueIndex, QueueExcute;
const QueueMaximun = Math.pow(2, 30) - 1;

let ARARParameter = function () {
	return {
		'rsvSrc': undefined,
		'rsvDest': undefined,
		'nodeLevel': undefined
	};
};

let ARARRule = function () {
	return {
		'order': undefined,
		'max_sip': undefined,
		'min_sip': undefined,
		'max_dip': undefined,
		'min_dip': undefined,
		'flag': false
	};
};

let TempRule = function () {
	return {
		'order': undefined,
		'max_sip': undefined,
		'min_sip': undefined,
		'max_dip': undefined,
		'min_dip': undefined,
		'max_slocate': undefined,
		'min_slocate': undefined,
		'max_dlocate': undefined,
		'min_dlocate': undefined,
	};
};

let ARARNode = function ( parameter ) {
	return {
		'parameter': parameter,
		'flag': false,
		'node0': undefined,
		'node1': undefined,
		'node2': undefined,
		'node3': undefined,
		'nodeRules': []
	};
};

function start ( ruleList ) {
	let newRuleList, parameter;
	
	newRuleList = rule_list_convert(ruleList);
	parameter = looking_for_region_segmentation_value(newRuleList);

	let ARARTree;
	ARARTree = arar_create( ruleList, newRuleList, parameter );

	let ruleGroupList;
	ruleGroupList = arar_tree_traversal( ARARTree, ruleList );
	// console.log(`\nruleGroupList:\n` + util.inspect( ruleGroupList, { showHidden: false, depth:null } ));
	return ruleGroupList;
};

function arar_create ( originalRuleList, ruleList, parameter ) {
	let ARARTreeRoot = new ARARNode( parameter );
	ARARTreeRoot['nodeRules'] = ruleList;
	if ( check_tcp_flag(originalRuleList, ruleList) ) {
		ARARTreeRoot['flag'] = true;
	}
	// console.log(`\nARARTreeRoot:\n` + util.inspect( ARARTreeRoot, { showHidden: false, depth:null } ));

	initial_queue();
	// console.log(`\nQueue:\n` + util.inspect( Queue, { showHidden: false, depth:null } ));
	add_to_queue( ARARTreeRoot );
	// console.log(`\nQueue:\n` + util.inspect( Queue, { showHidden: false, depth:null } ));
	let node;
	while ( true ){
		node = segmentation( delete_from_queue() );
		if ( node != null ) {
			// console.log(`baseSrc = ${baseSrc}, baseDest = ${baseDest}`);
			// console.log(`\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ));
			
			if ( node['node0'] != null )
				add_to_queue( node['node0'] );
			if ( node['node1'] != null )
				add_to_queue( node['node1'] );
			if ( node['node2'] != null )
				add_to_queue( node['node2'] );
			if ( node['node3'] != null )
				add_to_queue( node['node3'] );
		}
		else break;
	}

	
	// console.log(`\nARARTreeRoot:\n` + util.inspect( ARARTreeRoot, { showHidden: false, depth:null } ));
	return ARARTreeRoot;
};

function segmentation ( node ) {
	// check node exist
	if ( node == null ) {
		// console.log( `\x1b[1m[segmentation] node is null\x1b[0m` );
		return node;
	}

	// check rule in node with tcp-flag
	if ( node['flag'] == false ){
		// console.log( `\x1b[1m[segmentation] node without tcp-flag rule\x1b[0m\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ) + `\n` );
		return node;
	}

	// check thas is node need to be segment
	if ( !check_node_status( node ) ){
		// console.log(`\x1b[1m[segmentation] no need to segment\x1b[0m\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ) + `\n` );
		return node;
	}

	// console.log(`\x1b[1m[segmentation] need to segment\x1b[0m\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ) + `\n` );

	/* sip - dip
	 *  ---------
	 * | 01 | 11 |
	 * |----+----|
	 * | 00 | 10 |
	 *  ---------
	 */
	for (let i=0; i<node['nodeRules'].length; i++) {
		let locates, locateS, located, locateD, situation;
		let rsvSrcFull = ( baseSrc | node['parameter']['rsvSrc'] ) >>> 0,
			rsvDestFull = ( baseDest | node['parameter']['rsvDest'] ) >>> 0,
			currentRule = node['nodeRules'][i];

		locates =  Math.floor( currentRule['min_sip'] / rsvSrcFull );
		locateS =  Math.floor( currentRule['max_sip'] / rsvSrcFull );
		located =  Math.floor( currentRule['min_dip'] / rsvDestFull );
		locateD =  Math.floor( currentRule['max_dip'] / rsvDestFull );
		
		// min_sip  max_sip  min_dip  max_dip
		situation = `${locates}` + `${locateS}` + `${located}` + `${locateD}`;
		// console.log(`[${i}]th rule:`);
		// console.log(`locates:\t` + locates);
		// console.log(`locateS:\t` + locateS);
		// console.log(`located:\t` + located);
		// console.log(`locateD:\t` + locateD);
		// console.log(`situation:\t` + situation + '\n\n');
		switch ( situation ) {
			case '0000': // done
			/* case '0000'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * | * * |     |
			 * | * * |     |
			 *  -----------
			 */
				if ( node['node0'] == null )
					node['node0'] = new ARARNode( update_region_segmentation_value(currentRule, node['parameter']) );
				if ( currentRule['flag'] == true )
					node['node0']['flag'] = true;
				node['node0']['nodeRules'].push( currentRule );
				break;
			case '0011': // done
			/* case '0011'
			 *  -----------
			 * | * * |     |
			 * | * * |     |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */
				if ( node['node1'] == null )
					node['node1'] = new ARARNode( update_region_segmentation_value(currentRule, node['parameter']) );
				if ( currentRule['flag'] == true )
					node['node1']['flag'] = true;
				node['node1']['nodeRules'].push( currentRule );
				break;
			case '1100': // done
			/* case '1100'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * |     | * * |
			 * |     | * * |
			 *  -----------
			 */
				if ( node['node2'] == null )
					node['node2'] = new ARARNode( update_region_segmentation_value(currentRule, node['parameter']) );
				if ( currentRule['flag'] == true )
					node['node2']['flag'] = true;
				node['node2']['nodeRules'].push( currentRule );
				break;
			case '1111': // done
			/* case '1111'
			 *  -----------
			 * |     | * * |
			 * |     | * * |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */	
				if ( node['node3'] == null )
					node['node3'] = new ARARNode( update_region_segmentation_value(currentRule, node['parameter']) );
				if ( currentRule['flag'] == true )
					node['node3']['flag'] = true;
				node['node3']['nodeRules'].push( currentRule );
				break;
			case '0100': // done
			/* case '0100'
			 *  -----------
			 * |     |     |
			 * |     |     |
			 * |-----+-----|
			 * |   * | *   |
			 * |   * | *   |
			 *  -----------
			 */
				// for locate 00
				var ruleLocate00 = deepcopy( currentRule );
				ruleLocate00['max_sip'] = rsvSrcFull - 1;
				if ( node['node0'] == null )
					node['node0'] = new ARARNode( update_region_segmentation_value(ruleLocate00, node['parameter']) );
				if ( ruleLocate00['flag'] == true )
					node['node0']['flag'] = true;
				node['node0']['nodeRules'].push( ruleLocate00 );

				// for locate 10
				var ruleLocate10 = deepcopy( currentRule );
				ruleLocate10['min_sip'] = rsvSrcFull;
				if ( node['node2'] == null )
					node['node2'] = new ARARNode( update_region_segmentation_value(ruleLocate10, node['parameter']) );
				if ( ruleLocate10['flag'] == true )
					node['node2']['flag'] = true;
				node['node2']['nodeRules'].push( ruleLocate10 );

				break;
			case '0001': // done
			/* case '0001'
			 *  -----------
			 * |     |     |
			 * | * * |     |
			 * |-----+-----|
			 * | * * |     |
			 * |     |     |
			 *  -----------
			 */
				// for locate 00
				var ruleLocate00 = deepcopy( currentRule );
				ruleLocate00['max_dip'] = rsvDestFull - 1;
				if ( node['node0'] == null )
					node['node0'] = new ARARNode( update_region_segmentation_value(ruleLocate00, node['parameter']) );
				if ( ruleLocate00['flag'] == true )
					node['node0']['flag'] = true;
				node['node0']['nodeRules'].push( ruleLocate00 );

				// for locate 01
				var ruleLocate01 = deepcopy( currentRule );
				ruleLocate01['min_dip'] = rsvDestFull;
				if ( node['node1'] == null )
					node['node1'] = new ARARNode( update_region_segmentation_value(ruleLocate01, node['parameter']) );
				if ( ruleLocate01['flag'] == true )
					node['node1']['flag'] = true;
				node['node1']['nodeRules'].push( ruleLocate01 );

				break;
			case '0111': // done
			/* case '0111'
			 *  -----------
			 * |   * | *   |
			 * |   * | *   |
			 * |-----+-----|
			 * |     |     |
			 * |     |     |
			 *  -----------
			 */
				// for locate 01
				var ruleLocate01 = deepcopy( currentRule );
				ruleLocate01['max_sip'] = rsvSrcFull - 1;
				if ( node['node1'] == null )
					node['node1'] = new ARARNode( update_region_segmentation_value(ruleLocate01, node['parameter']) );
				if ( ruleLocate01['flag'] == true )
					node['node1']['flag'] = true;
				node['node1']['nodeRules'].push( ruleLocate01 );

				// for locate 11
				var ruleLocate11 = deepcopy( currentRule );
				ruleLocate11['min_sip'] = rsvSrcFull;
				if ( node['node3'] == null )
					node['node3'] = new ARARNode( update_region_segmentation_value(ruleLocate11, node['parameter']) );
				if ( ruleLocate11['flag'] == true )
					node['node3']['flag'] = true;
				node['node3']['nodeRules'].push( ruleLocate11 );

				break;
			case '1101': // done
			/* case '1101'
			 *  -----------
			 * |     |     |
			 * |     | * * |
			 * |-----+-----|
			 * |     | * * |
			 * |     |     |
			 *  -----------
			 */
			 	// for locate 10
				var ruleLocate10 = deepcopy( currentRule );
				ruleLocate10['max_dip'] = rsvDestFull - 1;
				if ( node['node2'] == null )
					node['node2'] = new ARARNode( update_region_segmentation_value(ruleLocate10, node['parameter']) );
				if ( ruleLocate10['flag'] == true )
					node['node2']['flag'] = true;
				node['node2']['nodeRules'].push( ruleLocate10 );

				// for locate 11
				var ruleLocate11 = deepcopy( currentRule );
				ruleLocate11['min_dip'] = rsvDestFull;
				if ( node['node3'] == null )
					node['node3'] = new ARARNode( update_region_segmentation_value(ruleLocate11, node['parameter']) );
				if ( ruleLocate11['flag'] == true )
					node['node3']['flag'] = true;
				node['node3']['nodeRules'].push( ruleLocate11 );
				
				break;
			case '0101': // done
			/* case '0101'
			 *  -----------
			 * |     |     |
			 * |   * | *   |
			 * |-----+-----|
			 * |   * | *   |
			 * |     |     |
			 *  -----------
			 */
				// for locate 00
				var ruleLocate00 = deepcopy( currentRule );
				ruleLocate00['max_sip'] = rsvSrcFull - 1;
				ruleLocate00['max_dip'] = rsvDestFull - 1;
				if ( node['node0'] == null )
					node['node0'] = new ARARNode( update_region_segmentation_value(ruleLocate00, node['parameter']) );
				if ( ruleLocate00['flag'] == true )
					node['node0']['flag'] = true;
				node['node0']['nodeRules'].push( ruleLocate00 );

				// for locate 01
				var ruleLocate01 = deepcopy( currentRule );
				ruleLocate01['max_sip'] = rsvSrcFull - 1;
				ruleLocate01['min_dip'] = rsvDestFull;
				if ( node['node1'] == null )
					node['node1'] = new ARARNode( update_region_segmentation_value(ruleLocate01, node['parameter']) );
				if ( ruleLocate01['flag'] == true )
					node['node1']['flag'] = true;
				node['node1']['nodeRules'].push( ruleLocate01 );

				// for locate 10
				var ruleLocate10 = deepcopy( currentRule );
				ruleLocate10['min_sip'] = rsvSrcFull;
				ruleLocate10['max_dip'] = rsvDestFull - 1;
				if ( node['node2'] == null )
					node['node2'] = new ARARNode( update_region_segmentation_value(ruleLocate10, node['parameter']) );
				if ( ruleLocate10['flag'] == true )
					node['node2']['flag'] = true;
				node['node2']['nodeRules'].push( ruleLocate10 );

				// for locate 11
				var ruleLocate11 = deepcopy( currentRule );
				ruleLocate11['min_sip'] = rsvSrcFull;
				ruleLocate11['min_dip'] = rsvDestFull;
				if ( node['node3'] == null )
					node['node3'] = new ARARNode( update_region_segmentation_value(ruleLocate11, node['parameter']) );
				if ( ruleLocate11['flag'] == true )
					node['node3']['flag'] = true;
				node['node3']['nodeRules'].push( ruleLocate11 );

				break;
			default:
				console.log(`\x1b[1m[segmentation] unexpect situation with ${situation}\x1b[1m`);
			return node;
		};
	}
	node['nodeRules'] = [];
	// console.log(`\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ) + `\n`);
	return node;
};

/* check_node_status()
 * 
 * [return value]
 * true: this node need to segment
 * false: this node won't need to segment
 */
function check_node_status ( node ) {
	// check number of rule in the node
	if ( node['nodeRules'].length >= 2 ) {
		// rule in node >= 2
		// console.log('rule number >= 2');
		if ( check_rule_range_difference( node['nodeRules'] ) ) {
			// different range
			// console.log('different range');
			return true;
		}
		else {
			// same range
			// console.log('same range');
			return false;
		}
	}
	else {
		// no rule in node, or only one rule in node
		// console.log('rule number < 2');
		return false;
	}
};

function check_rule_range_difference ( ruleList ) {
	// different as true, same as false
	// console.log(`\nruleList:\n` + util.inspect( ruleList, { showHidden: false, depth:null } ));
	for (let i=0; i<ruleList.length-1; i++) {
		// console.log( `ruleList:\t[${i}]th\tand\t[${i+1}]th is checking` );
		// console.log( `max_sip:\t${ruleList[i]['max_sip']},\t${ruleList[i+1]['max_sip']}` );
		// console.log( `max_dip:\t${ruleList[i]['max_dip']},\t${ruleList[i+1]['max_dip']}` );
		// console.log( `min_sip:\t${ruleList[i]['min_sip']},\t${ruleList[i+1]['min_sip']}` );
		// console.log( `min_dip:\t${ruleList[i]['min_dip']},\t${ruleList[i+1]['min_dip']}` );
		if ( ruleList[i]['max_sip'] != ruleList[i+1]['max_sip'] ||
		     ruleList[i]['max_dip'] != ruleList[i+1]['max_dip'] || 
		     ruleList[i]['min_sip'] != ruleList[i+1]['min_sip'] || 
		     ruleList[i]['min_dip'] != ruleList[i+1]['min_dip'] ) {
			return true;	// range different
		}
	}
	return false;	// range same
};

function check_tcp_flag ( originalRuleList, ruleList ) {
	// has tcp-flag as true, no tcp-flag as false
	for (let i=0; i<ruleList.length; i++)
		if ( originalRuleList[ruleList[i]['order']]['tcp_flag'] != null )
			return true;	// has tcp-flag
	return false;	// no tcp-flag
};

function update_region_segmentation_value ( rule, parameter ) {
	let newParameter = deepcopy( parameter );

	if ( rule['min_sip'] < ( ( newParameter['rsvSrc'] | baseSrc ) >>> 0 ) )
		newParameter['rsvSrc'] &= ( ~( rsvFirst >> ( newParameter['nodeLevel'] - 1 ) ) >>> 0 );
	newParameter['rsvSrc'] |= ( rsvFirst >> newParameter['nodeLevel'] );
	
	if ( rule['min_dip'] < ( ( newParameter['rsvDest'] | baseDest ) >>> 0 ) )
		newParameter['rsvDest'] &= ( ~( rsvFirst >>> ( newParameter['nodeLevel'] - 1 ) ) >>> 0 );
	newParameter['rsvDest'] |= ( rsvFirst >> newParameter['nodeLevel'] );

	newParameter['nodeLevel']++;
	
	// console.log(`\nnewParameter:\n` + util.inspect( newParameter, { showHidden: false, depth:null } ) + `\n`);
	return newParameter;
};



function arar_tree_traversal ( root, originalRuleList ) {
	let node;
	let ruleGroupList = [];

	if ( root['flag'] != true ) {
		console.log(`\nroot without tcp-flag\nroot:\n` + util.inspect( root, { showHidden: false, depth:null } ));
		return ruleGroupList;
	}

	initial_queue();
	add_to_queue( root );
	while( true ) {
		node = delete_from_queue();
		
		// console.log(`\nnode:\n` + util.inspect( node, { showHidden: false, depth:null } ));

		if ( node != null ) {
			if ( node['flag'] == true ) {
				if ( node['nodeRules'].length > 0 ) {
					let ruleGroup = rule_group_convert(originalRuleList, node['nodeRules']);
					if ( !check_rule_group_exist(ruleGroupList, ruleGroup) ){
						// console.log('no this group in list');
						ruleGroupList.push(ruleGroup);
					}
					else {
						// console.log(`\nthis group has already in list\ngroup:\n` + util.inspect( node['nodeRules'], { showHidden: false, depth:null } ));
					}
				}
				
				if ( ( node['node0'] != null ) && ( node['node0']['flag'] == true ) )
					add_to_queue( node['node0'] );
				if ( ( node['node1'] != null ) && ( node['node1']['flag'] == true ) )
					add_to_queue( node['node1'] );
				if ( ( node['node2'] != null ) && ( node['node2']['flag'] == true ) )
					add_to_queue( node['node2'] );
				if ( ( node['node3'] != null ) && ( node['node3']['flag'] == true ) )
					add_to_queue( node['node3'] );
			}
			else {
				console.log(`\nnode without tcp-flag\nroot:\n` + util.inspect( node, { showHidden: false, depth:null } ));
				continue;
			}		// node without tcp
		}
		else break;		// node is null
		
	}
	// console.log(`\nruleGroupList:\n` + util.inspect( ruleGroupList, { showHidden: false, depth: null } ));
	return ruleGroupList;
};

function rule_group_convert ( originalRuleList, ruleList ) {
	let newRuleList = [];
	for (let i=0; i<ruleList.length; i++) {
		newRuleList.push( originalRuleList[ruleList[i]['order']] );
		// newRuleList.push( ruleList[i]['order'] );
		// console.log(`\noriginalRuleList[ruleList['order']]:\n` + util.inspect( originalRuleList, { showHidden: false, depth:null } ));
		// console.log(`\nruleList['order']:\n` + util.inspect( ruleList[i]['order'], { showHidden: false, depth:null } ));
	}

	// console.log(`\noriginalRuleList:\n` + util.inspect( originalRuleList, { showHidden: false, depth:null } ));
	// console.log(`\nruleList:\n` + util.inspect( ruleList, { showHidden: false, depth:null } ));
	// console.log(`\nnewRuleList:\n` + util.inspect( newRuleList, { showHidden: false, depth:null } ));
	return newRuleList;
};

function check_rule_group_exist ( ruleGroupList, ruleGroup ) {
	if ( ruleGroupList.length == 0 ) {
		// no rule in ruleGroupList
		return false;
	}
	for (let i=0; i<ruleGroupList.length; i++) {
		// console.log(`\nruleGroupList[${i}].length = ${ruleGroupList[i].length} \nruleGroup.length = ${ruleGroup.length}`);
		if ( ruleGroupList[i].length == ruleGroup.length ) {
			// number of rule in the group is same
			for (let j=0; j<ruleGroup.length; j++) {
				// per-rule check that are they same
				if ( ruleGroupList[i][j] !== ruleGroup[j] ){
					// rules aren't same, break to next rule;
					// console.log(`\nruleGroupList[i][j] = ${ruleGroupList[i][j]}\nruleGroup[j] = ${ruleGroup[j]}`);
					break; 
				}
			}
			// an entry in ruleGroupList is same as ruleGroup
			return true;
		}
		else {
			// number of rule in the group is not same, continue to next ruleGroup.
			continue;
		}
	}
	return false;
};



function looking_for_region_segmentation_value ( ruleList ) {
	let maxSIP = ruleList[0]['max_sip'],
		minSIP = ruleList[0]['min_sip'],
		maxDIP = ruleList[0]['max_dip'],
		minDIP = ruleList[0]['min_dip'];
		parameter = new ARARParameter();
	
	for ( let i = 1; i < ruleList.length; i++) {
		if ( maxSIP < ruleList[i]['max_sip'] )
			maxSIP = ruleList[i]['max_sip'];
		if ( maxDIP < ruleList[i]['max_dip'] )
			maxDIP = ruleList[i]['max_dip'];
		if ( minSIP > ruleList[i]['min_sip'] )
			minSIP = ruleList[i]['min_sip'];
		if ( minDIP > ruleList[i]['min_dip'] )
			minDIP = ruleList[i]['min_dip'];
	};

	let MASK = Math.pow(2, 32) - 1;		//	= 255.255.255.255
	parameter['rsvSrc'] = Math.pow( 2, Math.floor( Math.log2( maxSIP^minSIP ) ) );
	parameter['rsvDest'] = Math.pow( 2, Math.floor( Math.log2( maxDIP^minDIP ) ) );

	rsvFirst = parameter['rsvSrc'] > parameter['rsvDest'] ? parameter['rsvSrc'] : parameter['rsvDest'];
	MASK = ( MASK << ( Math.log2( rsvFirst ) + 1 ) ) >>> 0;
	baseSrc = (minSIP & MASK) >>> 0;
	baseDest = (minDIP & MASK) >>> 0;

	parameter['rsvSrc'] = rsvFirst;
	parameter['rsvDest'] = rsvFirst;
	parameter['nodeLevel'] = 1;


	// console.log(`\nparameter:\n` + util.inspect( parameter, { showHidden: false, depth:null } ));
	// console.log( 'baseSrc: ' + myutils.ip_converter( baseSrc ) );
	// console.log( 'baseDest ' + myutils.ip_converter( baseDest ) );
	// console.log( 'parameter['rsvSrc']:  ' + myutils.ip_converter( parameter['rsvSrc'] ) );
	// console.log( 'parameter['rsvDest']: ' + myutils.ip_converter( parameter['rsvDest'] ) );
	// console.log( 'rsvFirst: ' + myutils.ip_converter( (rsvFirst) >>> 0 ) );
	// console.log( 'rsv: ' + myutils.ip_converter( (baseSrc|parameter['rsv']) >>> 0 ) );
	return parameter;
};



function rule_list_convert ( ruleList ) {
	let newRuleList = [];

	for (let i=0; i<ruleList.length; i++) {
		let rule = new ARARRule();
		rule['order'] = i;
		rule['max_sip'] = ruleList[i]['source_ip']['__param__']['boardcastAddrValue'];
		rule['min_sip'] = ruleList[i]['source_ip']['__param__']['networkAddrValue'];
		rule['max_dip'] = ruleList[i]['destination_ip']['__param__']['boardcastAddrValue'];
		rule['min_dip'] = ruleList[i]['destination_ip']['__param__']['networkAddrValue'];
		if ( ruleList[i]['tcp_flag'] != null )
			rule['flag'] = true;
		newRuleList.push(rule);
	}

	// console.log(`\nruleList:\n` + util.inspect( ruleList, { showHidden: false, depth:null } ));
	// console.log(`\nnewRuleList:\n` + util.inspect( newRuleList, { showHidden: false, depth:null } ));
	return newRuleList;
};



function initial_queue () {
	QueueExcute = 0;
	QueueIndex = 0;
	QueueNumber = 0;
	Queue = [];
	Queue[QueueNumber] = [];
};

function add_to_queue ( node ) {
	QueueIndex++;
	if ( QueueIndex == ( QueueMaximun - 1 ) ) {
		QueueIndex = 0;
		QueueNumber++;
	}
	Queue[QueueNumber][QueueIndex] = node;
};

function delete_from_queue () {
	Queue[QueueNumber][QueueExcute] = undefined;
	QueueExcute++;
	if ( QueueExcute == ( QueueMaximun - 1 ) ) {
		QueueExcute = 0;
		QueueNumber++;
	}
	return Queue[QueueNumber][QueueExcute];
};



module.exports.start = start;