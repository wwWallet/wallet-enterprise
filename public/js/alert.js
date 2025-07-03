popupAlert = (element_id, timeout="2000") => {
    document.getElementById(element_id).style.display = "block";
        window.scroll({
            top: 0,
            left: 0,
            behavior: 'smooth'
        });
        setTimeout(() => {
            document.getElementById(element_id).style.display = "none";
            }, timeout)
}
