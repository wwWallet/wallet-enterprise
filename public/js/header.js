// change language cookie (eg lang=en)
// refresh window

document.getElementById('lang-el').onclick = function (event) {
	document.cookie = 'lang=el; path=/'
	window.location.reload();
}

document.getElementById('lang-en').onclick = function (event) {
	document.cookie = 'lang=en; path=/';
	window.location.reload();
}