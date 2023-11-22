// change language cookie (eg lang=en)
// refresh window


if (document.getElementById('lang-el'))
	document.getElementById('lang-el').onclick = function (event) {
		document.cookie = 'lang=el; path=/'
		window.location.reload();
	}


if (document.getElementById('lang-en'))
	document.getElementById('lang-en').onclick = function (event) {
		document.cookie = 'lang=en; path=/';
		window.location.reload();
	}