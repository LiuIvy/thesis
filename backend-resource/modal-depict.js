const fs = require('fs');
modalHTML = fs.readFileSync(`${__dirname}/templates/firewall-modal.html`, 'utf-8').toString();

let modal = document.createElement('div');
modal.innerHTML = modalHTML;


function init ( obj ) {
	console.log('init');
	$(modal).insertAfter(`#main-container`);
	initlistener();


}

function update ( obj ) {
	console.log('update');
	initlistener();
}



function initlistener () {

$('#node-doubleclick-modal').on('show.bs.modal', function () {
	console.log('modal show');

	$('div#node-doubleclick-modal .modal-header h1').text();

	

	// if ( nodeBeenDoubleClicked.category === 'firewall' ) {}
	// else if ( nodeBeenDoubleClicked.category === 'network' ) {}

	// console.log($('div#node-doubleclick-modal .modal-header h1'));
	
	
});

$('#node-doubleclick-modal').on('shown.bs.modal', function () {
	console.log('modal shown');

	// Run when 'import-acl-button' in modal been clicked.
	$('#import-acl-button').on('click', function () {
		console.log('import-acl-button been click');
		// dialog.showOpenDialog( function ( filepath ) {
		// 	// filepath is an array that contains all the selected
		// 	console.log(filepath);
		// 	if ( filepath === undefined ) {
		// 		console.log("No file selected");
		// 		return;
		// 	}
		// 	curNodeACLObj = new ACLObject(filepath[0], nodeBeenDoubleClicked.key);
			
			// $('#modal-addtab-button').parent()
			// $(`#acl-tabs`).children('[id!=modal-addtab-li]').remove();
			// Object.keys(curNodeACLObj['ruleObject']).forEach(function ( keys, count ) {
			// 	$(`#${keys}`).remove();
			// 	$(`<li><a data-toggle="tab" href="#${keys}" aria-expanded="true">${keys}</a></li>`).insertBefore($('#modal-addtab-button').parent());
			// });
			// $(`#acl-tabs li:eq(1)`).addClass('active');
		// });
	});

	// Run when 'import-acl-button' in modal been clicked.
	$('#modal-addtab-button').on('click', function () {
		console.log('add tabs');
	});

	$('#modal-confirm-button').on('click', function () {
		console.log('modal confirm been click');
		// curThesisObj['aclObject'][nodeBeenDoubleClicked.key] = curNodeACLObj;
	});
});

/*	[modal hidding handler]
 *	Get the 
 */
$('#node-doubleclick-modal').on('hide.bs.modal', function () {
	console.log('modal hide');
});

$('#node-doubleclick-modal').on('hidden.bs.modal', function () {
	console.log('modal hidden');
});



}




module.exports.init = init;
module.exports.update = update;



function table_fill_in () {
	// ui part.
	let $acl_tbody = $('div[type="rules-table"]').find('tbody');
	let tr, td_in_out, td_protocol, td_srcip, td_destip, td_flag, td_action;

	tr = document.createElement('tr');
	td_in_out = document.createElement('td');
	td_order = document.createElement('td');
	td_protocol = document.createElement('td');
	td_srcip = document.createElement('td');
	td_destip = document.createElement('td');
	td_flag = document.createElement('td');
	td_action = document.createElement('td');

	td_in_out.innerHTML = in_out;

	$(tr).append(td_in_out, td_protocol, td_srcip, td_destip, td_flag, td_action).appendTo($acl_tbody);
}