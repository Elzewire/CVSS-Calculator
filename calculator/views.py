from math import ceil

from django.http import JsonResponse
from django.urls import reverse_lazy
from django.views.generic import TemplateView, RedirectView

from calculator.metrics import base_metrics, environmental_metrics, temporal_metrics, base_metrics3, temporal_metrics3, \
    environmental_metrics3


class IndexView(RedirectView):
    url = reverse_lazy("cvss2")


class Cvss2View(TemplateView):
    template_name = "calculator/cvss2.html"


class Cvss3View(TemplateView):
    template_name = "calculator/cvss3.html"


def CVSS2_calc(request):
    AC = base_metrics.get("AC").get(request.POST["AC"])
    Au = base_metrics.get("Au").get(request.POST["Au"])
    AV = base_metrics.get("AV").get(request.POST["AV"])
    C = base_metrics.get("Im").get(request.POST["C"])
    I = base_metrics.get("Im").get(request.POST["I"])
    A = base_metrics.get("Im").get(request.POST["A"])
    E = temporal_metrics.get("E").get(request.POST["E"])
    RL = temporal_metrics.get("RL").get(request.POST["RL"])
    RC = temporal_metrics.get("RC").get(request.POST["RC"])
    CDP = environmental_metrics.get("CDP").get(request.POST["CDP"])
    TD = environmental_metrics.get("TD").get(request.POST["TD"])
    CR = environmental_metrics.get("Re").get(request.POST["CR"])
    IR = environmental_metrics.get("Re").get(request.POST["IR"])
    AR = environmental_metrics.get("Re").get(request.POST["AR"])

    # Базовая метрика
    expl = 20 * AC * Au * AV
    imp = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))
    fimp = 0
    if imp != 0:
        fimp = 1.176

    base = round((0.6 * imp + 0.4 * expl - 1.5) * fimp, 1)

    # Временная метрика
    temp = round(base * E * RL * RC, 1)

    # Контекстная метрика
    aimp = min(10, 10.41 * (1 - (1 - C * CR) * (1 - I * IR) * (1 - A * AR)))
    abase = (0.6 * aimp + 0.4 * expl - 1.5) * fimp
    atemp = abase * E * RL * RC
    env = round(((atemp + (10 - atemp) * CDP) * TD), 1)

    bvec = "AV:{}/AC:{}/Au:{}/C:{}/I:{}/A:{}".format(
        request.POST["AV"], request.POST["AC"], request.POST["Au"],
        request.POST["C"], request.POST["I"], request.POST["A"]
    )

    tvec = "E:{}/RL:{}/RC:{}".format(
        request.POST["E"], request.POST["RL"], request.POST["RC"]
    )

    evec = "CDP:{}/TD:{}/CR:{}/IR:{}/AR:{}".format(
        request.POST["CDP"], request.POST["TD"], request.POST["CR"],
        request.POST["IR"], request.POST["AR"]
    )

    res = {
        "bscore": base,
        "tscore": temp,
        "escore": env,
        "bvec": bvec,
        "tvec": tvec,
        "evec": evec
    }

    return JsonResponse(res)

def round_up(x):
    return ceil(x * 10) / 10

def CVSS3_calc(request):
    AV = base_metrics3.get("AV").get(request.POST["AV"])
    AC = base_metrics3.get("AC").get(request.POST["AC"])
    S = base_metrics3.get("S").get(request.POST["S"])
    PR = base_metrics3.get("PR").get(request.POST["PR"]).get(S)
    UI = base_metrics3.get("UI").get(request.POST["UI"])
    C = base_metrics3.get("Im").get(request.POST["C"])
    I = base_metrics3.get("Im").get(request.POST["I"])
    A = base_metrics3.get("Im").get(request.POST["A"])

    E = temporal_metrics3.get("E").get(request.POST["E"])
    RL = temporal_metrics3.get("RL").get(request.POST["RL"])
    RC = temporal_metrics3.get("RC").get(request.POST["RC"])

    CR = environmental_metrics3.get("Re").get(request.POST["CR"])
    IR = environmental_metrics3.get("Re").get(request.POST["IR"])
    AR = environmental_metrics3.get("Re").get(request.POST["AR"])

    MAV = AV
    MAC = AC
    MS = S
    MPR = PR
    MUI = UI
    MC = C
    MI = I
    MA = A

    if request.POST["MAV"] != "X":
        MAV = environmental_metrics3.get("MAV").get(request.POST["MAV"])
    if request.POST["MAC"] != "X":
        MAC = environmental_metrics3.get("MAC").get(request.POST["MAC"])
    if request.POST["MS"] != "X":
        MS = environmental_metrics3.get("MS").get(request.POST["MS"])
    if request.POST["MPR"] != "X":
        MPR = environmental_metrics3.get("MPR").get(request.POST["MPR"]).get(MS)
    if request.POST["MUI"] != "X":
        MUI = environmental_metrics3.get("MUI").get(request.POST["MUI"])
    if request.POST["MC"] != "X":
        MC = environmental_metrics3.get("MIm").get(request.POST["MC"])
    if request.POST["MI"] != "X":
        MI = environmental_metrics3.get("MIm").get(request.POST["MI"])
    if request.POST["MA"] != "X":
        MA = environmental_metrics3.get("MIm").get(request.POST["MA"])

    # Базовая метрика
    expl = 8.22 * AV * AC * PR * UI
    imbase = 1 - ((1 - C) * (1 - I) * (1 - A))
    if S == 0:
        imp = 6.42 * imbase
        bscore = round_up(min(imp + expl, 10))
    else:
        imp = 7.52 * (imbase - 0.029) - 3.25 * (imbase - 0.02) ** 15
        bscore = round_up(min(1.08 * (imp + expl), 10))

    if imp <= 0:
        bscore = 0

    # Временная метрика
    tscore = round_up(bscore * E * RL * RC)

    # Контекстная метрика
    mexpl = 8.22 * MAV * MAC * MPR * MUI
    mimbase = min(1 - ((1 - MC * CR) * (1 - MI * IR) * (1 - MA * AR)), 0.915)
    if MS == 0:
        mimp = 6.42 * mimbase
        escore = round_up(round_up(min(mimp + mexpl, 10)) * E * RL * RC)
    else:
        mimp = 7.52 * (mimbase - 0.029) - 3.25 * (mimbase - 0.02) ** 15
        escore = round_up(round_up(min(1.08 * (mimp + mexpl), 10)) * E * RL * RC)

    if mimp <= 0:
        escore = 0

    bvec = "AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}".format(
        request.POST["AV"], request.POST["AC"], request.POST["PR"], request.POST["UI"], request.POST["S"],
        request.POST["C"], request.POST["I"], request.POST["A"]
    )

    tvec = "E:{}/RL:{}/RC:{}".format(
        request.POST["E"], request.POST["RL"], request.POST["RC"]
    )

    evec = "MAV:{}/MAC:{}/MPR:{}/MUI:{}/S:{}/MC:{}/MI:{}/MA:{}/CR:{}/IR:{}/AR:{}".format(
        request.POST["MAV"], request.POST["MAC"], request.POST["MPR"], request.POST["MUI"], request.POST["MS"],
        request.POST["MC"], request.POST["MI"], request.POST["MA"], request.POST["CR"], request.POST["IR"],
        request.POST["AR"]
    )

    res = {
        "bscore": bscore,
        "tscore": tscore,
        "escore": escore,
        "bvec": bvec,
        "tvec": tvec,
        "evec": evec
    }

    return JsonResponse(res)
