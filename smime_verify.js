

function popup_data(response)
{
  $('#smime_verify_hidden').html(response);
}

rcmail.addEventListener('plugin.popup_data', popup_data);

rcmail.addEventListener('init', function(evt) {
    
    $('#smime_verify_signature').qtip({
	
	content: {
            text: $('#smime_verify_hidden').html(); 
	}, 
	
	style: {
	    classes: 'qtip-blue'
	}
	
    });

});


