

const enc = new TextDecoder("utf-8");
let qrIsConsumed = false;
let url = document.getElementById('server-url').value; // issuer initiation handlers waiting for op_state to be returned
url = url.replace('http', 'ws'); // if https, will be converted to wss which is what we want
console.log("Server url = ", url);
const op_state = document.getElementById('op_state').value;
url = url + '/issuer/cross-device/ws/' + op_state;

// open a socket
let socket = new WebSocket(url);

// send message from the form
// document.forms.publish.onsubmit = function() {
//   let outgoingMessage = this.message.value;

//   socket.send(outgoingMessage);
//   return false;
// };

socket.binaryType = "arraybuffer";
// handle incoming messages
socket.onmessage = function (event) {
	let incomingMessage = event.data;
	console.log("Incoming messge = ", incomingMessage)
	const { taxisAuthorizationUrl } = JSON.parse(incomingMessage);
	// if the above fails, then try the bellow one
	// const { authorizationUrl } = JSON.parse(enc.decode(incomingMessage));
	// console.log('authorization url', authorizationUrl);
	qrIsConsumed = true;
	socket.close();
	window.location.href = taxisAuthorizationUrl;

	// showMessage(enc.decode(incomingMessage));
};

socket.onclose = event => !qrIsConsumed ? window.location.href = '/' : console.log();

// show message in div#messages
// function showMessage(message) {
//   let messageElem = document.createElement('div');
//   messageElem.textContent = message;
//   document.getElementById('messages').prepend(messageElem);
// }
