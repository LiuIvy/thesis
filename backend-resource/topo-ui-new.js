"use strict";

const pictures = `${__dirname}/pictures`;

let $s, myDiagram, myPalette;
let SD = {
	mode: 'pointer',
	itemType: 'pointer',
	nodeCounter: {
		network: 0,
		firewall: 0
	}
};


// valve是中間的點
function init (  ) {

	$s = go.GraphObject.make;

	

	
	myDiagram = $s(go.Diagram, 'topo-diagram', {
		initialContentAlignment: go.Spot.Center,
		'undoManager.isEnabled': true,
		// allowDrop: true,
		allowLink: false,  // linking is only started via buttons, not modelessly
		'animationManager.isEnabled': false,

		'linkingTool.portGravity': 0,  // no snapping while drawing new links
		'linkingTool.doActivate': function () {
			// change the curve of the LinkingTool.temporaryLink
			this.temporaryLink.curve = go.Link.Normal;
			this.temporaryLink.path.strokeWidth = 2;
			go.LinkingTool.prototype.doActivate.call(this);
		},
		// override the link creation process
		'linkingTool.insertLink': function ( fromnode, fromport, tonode, toport ) {
			// to control what kind of Link is created,
			// change the LinkingTool.archetypeLinkData's category
			myDiagram.model.setCategoryForLinkData(this.archetypeLinkData, SD.itemType);
			// Whenever a new Link is drawng by the LinkingTool, it also adds a node data object
			// that acts as the label node for the link, to allow links to be drawn to/from the link.
			this.archetypeLabelNodeData = (SD.itemType === 'flow') ? { category: 'valve' } : null;
			// also change the text indicating the condition, which the user can edit
			this.archetypeLinkData.text = SD.itemType;
			return go.LinkingTool.prototype.insertLink.call(this, fromnode, fromport, tonode, toport);
		},

		'clickCreatingTool.archetypeNodeData': {},  // enable ClickCreatingTool
		'clickCreatingTool.isDoubleClick': false,   // operates on a single click in background
		'clickCreatingTool.canStart': function () {  // but only in 'node' creation mode
			return SD.mode === 'node' && go.ClickCreatingTool.prototype.canStart.call(this);
		},
		'clickCreatingTool.insertPart': function (loc) {  // customize the data for the new node
			SD.nodeCounter[SD.itemType] += 1;
			var newNodeId = SD.itemType + SD.nodeCounter[SD.itemType];
			this.archetypeNodeData = {
				key: newNodeId,
				category: SD.itemType,
				label: newNodeId
			};
			return go.ClickCreatingTool.prototype.insertPart.call(this, loc);
		}
	});

	// install the NodeLabelDraggingTool as a 'mouse move' tool
	// myDiagram.toolManager.mouseMoveTools.insertAt(0, new NodeLabelDraggingTool());

	// when the document is modified, add a '*' to the title and enable the 'Save' button
	myDiagram.addDiagramListener('Modified', function(e) {
		var button = document.getElementById('SaveButton');
		if (button)
			button.disabled = !myDiagram.isModified;
		var idx = document.title.indexOf('*');
		if (myDiagram.isModified) {
			if (idx < 0)
				document.title += '*';
		}
		else {
			if (idx >= 0)
				document.title = document.title.substr(0, idx);
		}
	});

	// generate unique label for valve on newly-created flow link
	myDiagram.addDiagramListener('LinkDrawn', function(e) {
		var link = e.subject;
		if (link.category === 'flow') {
			myDiagram.startTransaction('updateNode');
			SD.nodeCounter.valve += 1;
			var newNodeId = 'flow' + SD.nodeCounter.valve;
			var labelNode = link.labelNodes.first();
			myDiagram.model.setDataProperty(labelNode.data, 'label', newNodeId);
			myDiagram.commitTransaction('updateNode');
		}
	});

	buildTemplates();
}

function buildTemplates () {
	// myDiagram Template setting
	myDiagram.nodeTemplateMap.add('firewall',
		$s(go.Node, 'Vertical', 
			{ 
				doubleClick: nodeDoubleClicked,
				fromLinkable: true,
				toLinkable: true
			},
			$s(go.TextBlock, 'Default Text', 
				{ font: "bold 16px sans-serif" },
				new go.Binding('text', 'key')),
			$s(go.Picture, 
				{ source: `${pictures}/firewall-gray.png`, width: 50, height: 50 }
				)));

	myDiagram.nodeTemplateMap.add('network',
		$s(go.Node, 'Vertical',
			{
				doubleClick: nodeDoubleClicked,
				fromLinkable: true,
				toLinkable: true
			},
			$s(go.TextBlock, 'Default Text', 
				{ font: "bold 16px sans-serif" },
				new go.Binding('text', 'key')),
			$s(go.Picture, 
				{ source: `${pictures}/network.png`, width: 50, height: 50 }
				)));

	myDiagram.linkTemplateMap.add('', $s(go.Link, $s(go.Shape)));
	myDiagram.linkTemplateMap.add('link', $s(go.Link, $s(go.Shape)));

	

	// myPalette Template setting
	myPalette = $s(go.Palette, 'topo-palette');

	myPalette.nodeTemplateMap.add('pointer',
		$s(go.Node, 'Auto', { click: paletteLinkClicked },
			$s(go.Picture, 
				{ source: `${pictures}/mouse.jpg`, width: 50, height: 50 }
				)));

	myPalette.nodeTemplateMap.add('firewall',
		$s(go.Node, 'Auto', { click: paletteLinkClicked },
			$s(go.Picture, 
				{ source: `${pictures}/firewall.png`, width: 50, height: 50 }),
			$s(go.TextBlock, 'Default Text',
				{ font: "bold 16px sans-serif" },
				new go.Binding('text', 'key'))
			));

	myPalette.nodeTemplateMap.add('network',
		$s(go.Node, 'Auto', { click: paletteLinkClicked },
			$s(go.Picture, 
				{ source: `${pictures}/network.png`, width: 50, height: 50 }),
			$s(go.TextBlock, 'Default Text',
				{ font: "bold 16px sans-serif" },
				new go.Binding('text', 'key'))
			));

	myPalette.nodeTemplateMap.add('link',
		$s(go.Node, 'Auto', { click: paletteLinkClicked },
			$s(go.Picture, 
				{ source: `${pictures}/link.png`, width: 50, height: 50 }),
			$s(go.TextBlock, 'Default Text',
				{ font: "bold 16px sans-serif" },
				new go.Binding('text', 'key'))
			));

	myPalette.model = new go.GraphLinksModel([
		{ category: "pointer" },
		{ category: "network", key: 'nw' },
		{ category: "firewall", key: 'fw' },
		{ category: "link", key: 'link' }
		]);





	let nodeDataArray = [
		{ category: "network", key: 'nw1' },
		{ category: "network", key: 'nw2' },
		{ category: "firewall", key: 'fw1' },
		{ category: "firewall", key: 'fw2' },
		{ category: "firewall", key: 'fw3' }
	];

	let linkDataArray = [
		{ from: 'nw1', to: 'fw1' },
		{ from: 'fw1', to: 'fw2' },
		{ from: 'fw1', to: 'fw3' },
		{ from: 'fw2', to: 'fw3' },
		{ from: 'fw2', to: 'nw2' }
	];

	let model = new go.GraphLinksModel(nodeDataArray, linkDataArray);
	myDiagram.model = model;

	// console.log(model.toJson());
}


function nodeDoubleClicked ( e, obj ) {
	let evt = e.copy();
	let node = obj.part;
	let type = evt.clickCount === 2 ? "Double-Clicked: " : "Clicked: ";
	let msg = type + node.data.key + '. ';
	// document.getElementById('topo-diagram-status').textContent = msg;
}

function paletteLinkClicked ( e, obj ) {
	myDiagram.startTransaction();
	let mode;

	let evt = e.copy();
	let node = obj.part;
	let type = evt.clickCount === 2 ? "Double-Clicked: " : "Clicked: ";
	let msg = type + node.data.key + '. ';
	// document.getElementById('topo-palette-status').textContent = msg;

	
	SD.itemType = node.data.category;
	if ( SD.itemType === 'firewall' || SD.itemType === 'network' ){
		mode = SD.mode = 'node';
	}
	else{
		mode = SD.mode = node.data.category;
	}

	console.log(SD);
	if ( mode === 'pointer' ) {
		myDiagram.allowLink = false;
		myDiagram.nodes.each(function ( n ) { n.port.cursor = ''; });
	} else if (mode === 'node') {
		myDiagram.allowLink = false;
		myDiagram.nodes.each(function ( n ) { n.port.cursor = ''; });
	} else if (mode === 'link') {
		myDiagram.allowLink = true;
		myDiagram.nodes.each(function ( n ) { n.port.cursor = 'pointer'; });
	}
	myDiagram.commitTransaction('mode changed');


	console.log(myDiagram.model.toJson());
}
// function save () {}

// function load () {}



module.exports.init = init;