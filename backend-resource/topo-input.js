/**
 * Declare variables sector.
 * */
const fs = require('fs');
const path = require('path');
const _ = require('underscore');
// const dataProcess = require( path.join(__dirname, 'dataProcess.js') );
const topoParser = require( path.join(__dirname, 'topo-input-parser.js') );
// const anomaly = require( path.join(__dirname, 'anomaly.js') );
// const ui = require( path.join(__dirname, 'ui.js') );
const topoUI = require( path.join(__dirname, 'topo-ui-new.js') );
// const TreeModel = require('tree-model');
const util = require('util'); // debug

// let tree = new TreeModel();
let $rule_input = $('#topo-input');

/**
 * Initial sector when loaded.
 * */
$rule_input.fileinput();
topoUI.init();

/* update button onclick event. */
$('button[class~="fileinput-upload-button"]').attr('type', 'button').on('click', function() {
    console.log('Upload button has been pressed.');
    //** clean old ui.
    // $('#mypage-body').remove();
    //** parse rules.
    rules_import_handler(document.getElementById('topo-input').files[0].path);
    
});

$rule_input.on('fileclear', function(event) {
    $('#mypage-body').remove();
    console.log("fileclear");
});

$rule_input.on('fileloaded', function(event, file, previewId, index, reader) {
    console.log("fileloaded");
});

/**
 * Methods sector.
 * */
function rules_import_handler (filepath) {
    // clean temp_rulesData first.
    console.log(filepath);
    let lineList = [];


    fs.readFileSync(filepath).toString().split('\n').forEach( (line) => {
        lineList.push(line);
    });
    // policy_parser(lineList);
    console.log(lineList);

    topo = {};
    topo['nodes'] = [
        { 'type': 'fw', 'name': 'fw1' },
        { 'type': 'fw', 'name': 'fw2' },
        { 'type': 'fw', 'name': 'fw3' },
        { 'type': 'nw', 'name': 'nw1' },
        { 'type': 'nw', 'name': 'nw2' },
    ];
    topo['links'] = [
        { from: 'nw1', to: 'fw1' },
        { from: 'fw1', to: 'fw2' },
        { from: 'fw1', to: 'fw3' },
        { from: 'fw2', to: 'fw3' },
        { from: 'nw2', to: 'fw2' },
    ];

    console.log(topo);
    
}


$('button[id="load-button"]').attr('type', 'button').on('click', function() {
    console.log('load-button pressed');
});

$('button[id="save-button"]').attr('type', 'button').on('click', function() {
    console.log('save-button pressed');
});