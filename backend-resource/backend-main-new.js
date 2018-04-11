"use strict";

const fs = require('fs');
const path = require('path');
const _ = require('underscore');
const {dialog} = require('electron').remote;
// const ruleObject = require( path.join(__dirname, 'topo-input-parser.js') );
const topoUI = require( path.join(__dirname, 'topo-ui.js') );
const util = require('util'); // debug

const ruleObject = require( './acl-file-parser.js');

let curThesisObj, myDiagram, $s;



/*	[load button Handler]
 *	To import a exist project file into Programming.
 */
$('button[id="project-load-button"]').attr('type', 'button').on('click', function() {
	console.log('load-button pressed');

	dialog.showOpenDialog( function ( filepath ) {
		// filepath is an array that contains all the selected
		console.log(filepath);
		if ( filepath === undefined ) {
			console.log("No file selected");
			return;
		}
		fs.readFile(filepath[0], 'utf-8', function ( err, data ) {
			if ( err ) {
				alert("An error ocurred reading the file :" + err.message);
				return;
			}
			myObject = new myThesisObject(JSON.parse(data));
			myObject.update();
		});
	});
});

/*	[load button Handler]
 *	If it's a new project, there will be 'save-as' new file.
 *	If it's a object have been loaded or saved, there will be 'update' file.
 */
$('button[id="project-save-button"]').attr('type', 'button').on('click', function () {
	console.log('save-button pressed');
	if ( myObject.filepath === null ) {
		dialog.showSaveDialog( function ( filepath ) {
			if ( filepath === undefined ) {
				console.log("You didn't save the file");
				return;
			}
			// filepath is a string that contains the path and filename created in the save file dialog.
			myObject.filepath = filepath;
			fs.writeFile(myObject.filepath, JSON.stringify(myObject), function ( err ) {
				if(err){
					alert("An error ocurred creating the file "+ err.message)
				}
				alert("The file has been succesfully saved");				
			});
		});
	} else {
		fs.writeFile(myObject.filepath, JSON.stringify(myObject), function ( err ) {
			if (err) {
				alert("An error ocurred updating the file" + err.message);
				console.log(err);
				return;
			}
			alert("The file has been succesfully updated");
		});
	}
});




/*	[myThesisObject Constructor]
 *	If it's a new project, there will be 'save-as' new file.
 *	If it's a object have been loaded or saved, there will be 'update' file.
 */
function myThesisObject ( item=null ) {
	if ( item === null) {
		this.filepath = null;
		this.nodeDataArray = [];
		this.linkDataArray = [];
		this.aclObject = {};
		
	}
	else {
		this.filepath = item.filepath;
		this.nodeDataArray = item.nodeDataArray;
		this.linkDataArray = item.linkDataArray;
		this.aclObject = item.aclObject;
		
	}

	this.showObject = function ( mode=false ) {
		if ( mode )
			console.log(util.inspect( this, { showHidden: false, depth:null } ));
		else
			console.log(this);
	}
	this.start = function () {
		diagramInit(this);
	}
	this.update = function () {
		topoUI.update(this);
	}

	
}


function diagramInit ( thesisObject ) {
	$s = go.GraphObject.make;
	curThesisObj = thesisObject;
	myOperate = new diagramOperate();

	myDiagram = $s(go.Diagram, 'topo-diagram', {
		initialContentAlignment: go.Spot.Center,
		allowLink: false,	// linking is only started via buttons, not modelessly
		// 'undoManager.isEnabled': true
		"animationManager.isEnabled": false,
		"linkingTool.portGravity": 0,	// no snapping while drawing new links
		"linkingTool.doActivate": function() {
			// change the curve of the LinkingTool.temporaryLink
			this.temporaryLink.curve = go.Link.Normal;
			this.temporaryLink.path.stroke = 'black';
			this.temporaryLink.path.strokeWidth = 2;
			go.LinkingTool.prototype.doActivate.call(this);
		},

		// override the link creation process
		"linkingTool.insertLink": function(fromnode, fromport, tonode, toport) {
			myDiagram.model.setCategoryForLinkData(this.archetypeLinkData, myOperate.itemType);
			return go.LinkingTool.prototype.insertLink.call(this, fromnode, fromport, tonode, toport);
		},

		"clickCreatingTool.archetypeNodeData": {},  // enable ClickCreatingTool
		"clickCreatingTool.isDoubleClick": false,   // operates on a single click in background
		"clickCreatingTool.canStart": function() {  // but only in "node" creation mode
			return myOperate.mode === 'node' && go.ClickCreatingTool.prototype.canStart.call(this);
		},
		"clickCreatingTool.insertPart": function ( loc ) {  // customize the data for the new node
			myOperate.nodeCounter[myOperate.itemType] += 1;
			var newNodeId = myOperate.itemType + myOperate.nodeCounter[myOperate.itemType];
			this.archetypeNodeData = {
				key: newNodeId,
				category: myOperate.itemType,
				// label: newNodeId
			};
			return go.ClickCreatingTool.prototype.insertPart.call(this, loc);
		}
	});

	// not nessacery
	{
		// install the NodeLabelDraggingTool as a "mouse move" tool
		// myDiagram.toolManager.mouseMoveTools.insertAt(0, new NodeLabelDraggingTool());

		// when the document is modified, add a "*" to the title and enable the "Save" button
		// myDiagram.addDiagramListener("Modified", function(e) {
		// 	// var button = document.getElementById("SaveButton");
		// 	// if (button) button.disabled = !myDiagram.isModified;
		// 	var idx = document.title.indexOf("*");
		// 	if (myDiagram.isModified) {
		// 		if (idx < 0) document.title += "*";
		// 	} else {
		// 		if (idx >= 0) document.title = document.title.substr(0, idx);
		// 	}
		// });
	}
	buildTemplates();
	update(curThesisObj);

	function buildTemplates () {

		function textStyle() {}
		function nodeStyle() {}
		function firewallStyle() {}
		function networkStyle() {}



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
					// { source: `${pictures}/firewall-gray.png`, width: 50, height: 50 }
					{ source: `${pictures}/firewall.png`, width: 50, height: 50 }
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
	}

}








 module.exports = myThesisObject;


/*
 *	In initial of Programming, there is a new(blank) project been prepared.
 */



// for test the object change
{
	// $('button[id="setting"]').attr('type', 'button').on('click', function() {
	// 	// myObject.count++;
	// 	// console.log('count = ' + myObject.count);
	// 	console.log('setting pressed');

	// 	dialog.showOpenDialog( function ( filepath ) {
	// 		// filepath is an array that contains all the selected
	// 		console.log(filepath);
	// 		if ( filepath === undefined ) {
	// 			console.log("No file selected");
	// 			return;
	// 		}
	// 		let test = new aclObject(filepath[0]);
	// 		console.log(test);
	// 	});
	// });

	$('button[id="show-object"]').attr('type', 'button').on('click', function() {
		myObject.showObject();
	});
}