$('#otp_form').on('submit', async (e) => {

    e.preventDefault();
    sendOTP();
});

$('#otp').on('input', () => {

    const pattern_6digits = /^\d{6}$/;
    const otp = $('#otp').val();

    if (pattern_6digits.test(otp) && otp.length === 6)
        sendOTP();
})

const sendOTP = async () => {

    var formData = new FormData(document.getElementById('otp_form'));

    const url = DOMAIN + '/api/otp.php';
    const method = 'POST';

    try {
        const response = await fetch(url, 
        {
            method: method,
            body: formData,
        });

        if (response.ok)
        {
            // test
            //console.log(await response.text());
            //return false;
            
            const json = await response.json();
            window.location.href = json.redirect;
        }
        else
        {
            const errorTxt = await response.text();
            const errorJson = JSON.parse(errorTxt);
            $('#error_box').css("display", "block");
            $('#error_box').html(errorJson.status_message);
        }

    } catch (error) {
        console.log(error)
        $('#error_box').css("display", "block");
        $('#error_box').html("There was a problem, try again");
    }
}