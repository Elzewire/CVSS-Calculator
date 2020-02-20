function setActive(group, btn) {

    var gr = document.getElementsByClassName("btn-group");
    var bt = gr[group].getElementsByClassName("btn");
    for (var j = 0; j < bt.length; j++) {
        bt[j].classList.remove("active");
    }
    bt[btn].className += " active";
}