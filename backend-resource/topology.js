function Topology ( name ) {
	const stackMaximun = Math.pow(2, 30) - 1;
	let firewalls = [], networks = [],
		nodeCount = 0, nodeList = [],
		ifCount = {},
		topoObject = {}, topoArray = [],
		pathArray = [];

	this.addFirewall = function addFirewall ( name ) {
		let fw;
		if ( name )
			fw = {'type': 'fw', 'name': name};
		else 
			fw = {'type': 'fw'};
		firewalls.push(fw);
		ifCount[fw['name']] = [];
		return fw;
	}

	this.addNetwork = function addNetwork ( name, address ) {
		let nw;
		if ( address ) {
			addrSplit = address.trim().split('/');
			nw = {
				'type': 'nw',
				'name': name,
				'ip': addrSplit[0],
				'mask': addrSplit[1]
			};
		}
		else 
			nw = {'type': 'nw'};
		networks.push(nw);
		return nw;
	}

	this.addLink = function addLink ( node1, node2 ) {
		if ( !checkNodeExist(node1) ) {
			nodeCount++;
			nodeList.push(node1);
			topoObject[node1['name']] = {};
		}
		if ( !checkNodeExist(node2) ) {
			nodeCount++;
			nodeList.push(node2);
			topoObject[node2['name']] = {};
		}

		if ( node1['type'] == 'fw' ) {
			ifCount[node1['name']][ifCount[node1['name']].length] = ifCount[node1['name']].length;
		}
		if ( node2['type'] == 'fw' ) {
			ifCount[node2['name']][ifCount[node2['name']].length] = ifCount[node2['name']].length;
		}

		// topoObject generate
		for (let i=0; i<nodeList.length; i++) {
			for (let j=0; j<nodeList.length; j++) {
				if ( i == j ) {
					// topoObject[nodeList[i]['name']][nodeList[j]['name']] = undefined;
				}
				else {
					if ( nodeList[j] == node1 || nodeList[j] == node2 ) {
						if ( node1['type'] == 'nw' || node2['type'] == 'nw' ) {
							if ( node1['type'] == 'nw' && node2['type'] == 'fw' ) {
								topoObject[node1['name']][node2['name']] = true;
								topoObject[node2['name']][node1['name']] = 'eth' + ifCount[node2['name']][ifCount[node2['name']].length-1];
							}
							if ( node1['type'] == 'fw' && node2['type'] == 'nw' ) {
								topoObject[node1['name']][node2['name']] = 'eth' + ifCount[node1['name']][ifCount[node1['name']].length-1];
								topoObject[node2['name']][node1['name']] = true;
							}
						}
						else {
							topoObject[node1['name']][node2['name']] = 'eth' + ifCount[node1['name']][ifCount[node1['name']].length-1];
							topoObject[node2['name']][node1['name']] = 'eth' + ifCount[node2['name']][ifCount[node2['name']].length-1];
						}
					}
				}
			}
		}



		// convert topoObject to topoArray
		let Count = 0;
		Object.keys(topoObject).forEach((first) => {
			let innerCount = 0;
			topoArray[Count] = [];
			Object.keys(topoObject[first]).forEach((second) => {
				topoArray[Count][innerCount] = topoObject[first][second];
				innerCount++;
			});
			Count++;
		});


	}

	this.checkLink = function checkLink () {}

	this.showPath = function showPath () {
		console.log('\n\n');
		for (let i=0; i<networks.length; i++) {
			for (let j=0; j<networks.length; j++) {
				if ( i == j )
					continue;
				get_path(networks[i]['name'], networks[i]['name']);
			}
			
		}

		// console.log(`\n\npathArray:`);
		// console.log(pathArray);
	}


	function get_path ( node1, node2 ) {
		let nextNode, node;
		let stackIndex, stackExcute, stackNumber, stack;
		let path = [];
		let counter = 0;

		initial_stack();
		add_to_stack(node1);
		while ( true ) {
			node = delete_from_stack();

			if ( node ){
				if ( node == node2 ){
					// add to path and exit.
					continue;
				}
				nextNode = get_next_node(node);
				for (let i=0; i<nextNode.length; i++) {
					// if ( check_node_been_path(nextNode[i]) )
					add_to_stack(nextNode[i]);
				}
			}
			
		}

		
		function get_next_node ( node ) {
			let nextNode = [];
			Object.keys(topoObject[node]).forEach((keys) => {
				nextNode.push(keys);
			});
			return nextNode;
		}

		function check_node_been_path ( node, path ) {}


		function initial_stack () {
			stackExcute = 0;
			stackIndex = 0;
			stackNumber = 0;
			stack = [];
			stack[stackNumber] = [];
		}
		function add_to_stack ( node ) {
			stackIndex++;
			if ( stackIndex == ( stackMaximun - 1 ) ) {
				stackIndex = 0;
				stackNumber++;
			}
			stack[stackNumber][stackIndex] = node;
		}
		function delete_from_stack () {
			stack[stackNumber][stackExcute] = undefined;
			stackExcute++;
			if ( stackExcute == ( stackMaximun - 1 ) ) {
				stackExcute = 0;
				stackNumber++;
			}
			return stack[stackNumber][stackExcute];
		}
	}

	

	this.showTopology = function showTopology () {
		// console.log(`firewalls:`);
		// console.log(firewalls);
		// console.log(`networks:`);
		// console.log(networks);
		// console.log(`nodeList:`);
		// console.log(nodeList);
		// console.log(`ifCount:`);
		// console.log(ifCount);
		console.log(`topoObject:`);
		console.log(topoObject);
	}

	function checkNodeExist ( node ) {
		for (let i=0; i<nodeList.length; i++)
			if ( node === nodeList[i] )
				return true;
		return false;
	}

	
}
module.exports.Topology = Topology;