$("#calc").click(function () {
    $.ajax({
        url: "/cvss3/calc/",
        method: "POST",
        dataType: "json",
        data: {
            csrfmiddlewaretoken: document.getElementsByName("csrfmiddlewaretoken")[0].value,
            AV: $("#AV .active")[0].id,
            AC: $("#AC .active")[0].id,
            PR: $("#PR .active")[0].id,
            UI: $("#UI .active")[0].id,
            S: $("#S .active")[0].id,
            C: $("#C .active")[0].id,
            I: $("#I .active")[0].id,
            A: $("#A .active")[0].id,
            E: $("#E .active")[0].id,
            RL: $("#RL .active")[0].id,
            RC: $("#RC .active")[0].id,
            CR: $("#CR .active")[0].id,
            IR: $("#IR .active")[0].id,
            AR: $("#AR .active")[0].id,
            MAV: $("#MAV .active")[0].id,
            MAC: $("#MAC .active")[0].id,
            MPR: $("#MPR .active")[0].id,
            MUI: $("#MUI .active")[0].id,
            MS: $("#MS .active")[0].id,
            MC: $("#MC .active")[0].id,
            MI: $("#MI .active")[0].id,
            MA: $("#MA .active")[0].id,
        },
        success: function (data) {
            $("#results").show();
            $("#bscore").text("Базовая оценка: " + data.bscore);
            $("#tscore").text("Временная оценка: " + data.tscore);
            $("#escore").text("Контекстная оценка: " + data.escore);

            $("#bvec").text("Вектор: " + data.bvec);
            $("#tvec").text("Вектор: " + data.tvec);
            $("#evec").text("Вектор: " + data.evec);
        }
    })
});