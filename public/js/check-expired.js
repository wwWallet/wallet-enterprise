function updateLayoutForExpiredCredentials(credentialPayloads) {
	const currentDate = new Date();
	credentialPayloads.forEach((credential, index) => {
		const expirationDate = new Date(credential.expirationDate);
		const [crlURL, id] = credential.credentialStatus.id.split('#');
		fetch(crlURL).then((response) => {
			return response.json();
		}).then(({ crl }) => {
			console.log("CRL = ", crl);
			const record = crl.filter((rec) => rec.id == id)[0];
			if (record.revocation_date != null) { // is revoked
				const credentialBox = document.querySelectorAll('.credential-box')[index];
				credentialBox.classList.add('revoked-credential');
				const revokedLabel = document.createElement('div');
				revokedLabel.className = 'revoked-label';
				revokedLabel.textContent = 'Revoked';
				credentialBox.appendChild(revokedLabel);
			}
			else if (expirationDate < currentDate) {
				const credentialBox = document.querySelectorAll('.credential-box')[index];
				credentialBox.classList.add('expired-credential');
				const expiredLabel = document.createElement('div');
				expiredLabel.className = 'expired-label';
				expiredLabel.textContent = 'Expired';
				credentialBox.appendChild(expiredLabel);
			}
		})
	});
}