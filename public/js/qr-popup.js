const qrDialog = document.getElementById('qrDialog');
const qrImage = document.getElementById('qrImage');
const qrURL = document.getElementById('qrURL');
const closeDialogBtn = document.getElementById('closeDialogBtn');
const userPinTextElement = document.getElementById('userPinTextElement');
const wwwalletUrl = document.getElementById('wwwalletURL')

function openDialog(qrCodeURL, url, user_pin_required, user_pin) {
	qrImage.src = qrCodeURL;
	if (user_pin_required && user_pin_required == 'true') {
		userPinTextElement.innerHTML = `PIN: ${user_pin}`;
	}
	qrURLwwwallet.onclick = (e) => {
		url = url.replace('openid-credential-offer://', wwwalletUrl.value);
		console.log(url);
		e.preventDefault();
		window.location.href = url;
	}
	qrURLnative.onclick = (e) => {
		e.preventDefault();
		window.location.href = url;
	}
	qrDialog.showModal();
}

function closeDialog() {
	qrDialog.close();
}

// Handle "Scan QR" button click
const scanQRButtons = document.querySelectorAll('.credential .Btn.Small.ScanQRBtn');
scanQRButtons.forEach(button => {
	button.addEventListener('click', () => {
		const credentialOfferQR = button.dataset.credentialOfferQR;
		openDialog(credentialOfferQR);
	});
});

closeDialogBtn.addEventListener('click', closeDialog);
