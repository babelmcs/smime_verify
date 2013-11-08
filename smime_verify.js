var signatureInfo = "cane"; 

function popup_data()
{
   
    signatureInfo = "gatto";
    alert('funziona');
    
    return true;
    
};

function getSignatureInfo(){
    
    return signatureInfo;
    
};


rcmail.addEventListener('init', function(evt) {  

    $('#smime_verify_signatureOK').qtip({
		
	content: {
            text: $('#smime_verify_info_container').html() 
        },
		
	style: {
	    classes: 'qtip-green'
	}
	
    });
    
    $('#smime_verify_signatureFAILED').qtip({
		
	content: {
            text: $('#smime_verify_info_container').html() 
        },
		
	style: {
	    classes: 'qtip-red'
	}
	
    });


});


