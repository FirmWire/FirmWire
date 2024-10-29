import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import firmwire
from firmwire.emulator.init import MachineInitParams
from firmwire.util.misc import download_url

SHANNON_MODEM_URL = 'https://github.com/grant-h/ShannonFirmware/raw/master/modem_files/CP_G973FXXS5CTD1_CP15661447_CL18242812_QB30535823_REV01_user_low_ship.tar.md5.lz4'
MTK_MODEM_URL = 'https://zenodo.org/record/6516030/files/CP_A415FXXU1ATE1_CP15883562_CL18317596_QB31188168_REV00_user_low_ship_MULTI_CERT.tar.md5?download=1'

def setup():
    global SHANNON_MODEM_FILE, MTK_MODEM_FILE
    MTK_MODEM_FILE = download_url(MTK_MODEM_URL)
    SHANNON_MODEM_FILE = download_url(SHANNON_MODEM_URL)
    assert MTK_MODEM_FILE, SHANNON_MODEM_FILE

def test_shannon_basic():
    setup()
    workspace = firmwire.ScratchWorkspace()
    workspace.create()

    loader = firmwire.loader.load(SHANNON_MODEM_FILE, workspace, "shannon")
    assert loader is not None

    machine = loader.get_machine()
    assert machine is not None

    params = MachineInitParams()
    params.validate()

    assert machine.initialize(loader, params)

    machine.run_for(5)
    machine.avatar.shutdown()

def test_mtk_basic():
    setup()
    workspace = firmwire.ScratchWorkspace()
    workspace.create()
    empty_nv = workspace.base_path() / "empty"

    empty_nv_sub = empty_nv / "vendor" / "nvdata"
    empty_nv_sub.mkdir(parents=True)

    loader = firmwire.loader.load(MTK_MODEM_FILE, workspace, "mtk", nv_data=empty_nv)
    assert loader is not None

    machine = loader.get_machine()
    assert machine is not None

    params = MachineInitParams()
    params.validate()

    assert machine.initialize(loader, params)

    machine.run_for(5)
    machine.avatar.shutdown()
