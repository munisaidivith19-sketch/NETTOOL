"""Put the simulator's SSH logins into the agent's encrypted credential store.

Run from the agent folder (venv active, .env set up):   python -m simulation.setup_credentials

It adds one profile per simulated Cisco device (a /32 match on its management IP, port 2222).
The passwords are the public lab values from simulation/ssh_sim.py: they only open the
simulator. For real devices use `python -m netmap_agent.credential_store add` instead, which
asks for the password without echoing it.
"""

from netmap_agent.config import get_settings
from netmap_agent.credential_store import CredentialStore, Profile
from simulation.ssh_sim import (
    SIM_ENABLE_SECRET,
    SIM_SSH_PASSWORD,
    SIM_SSH_USER,
    SSH_DEVICES,
    SSH_PORT,
)


def profiles() -> list[Profile]:
    return [Profile(name=f"sim-{device.slug}", match=f"{device.listen}/32", device_type="cisco_ios",
                    username=SIM_SSH_USER, password=SIM_SSH_PASSWORD, secret=SIM_ENABLE_SECRET,
                    ssh_port=SSH_PORT)
            for device in SSH_DEVICES]


def main() -> None:
    settings = get_settings()
    store = CredentialStore(settings.credential_store_path,
                            settings.credential_store_key.get_secret_value())
    for profile in profiles():
        store.add(profile)
        print(f"  added {profile.name:<20} {profile.match:<16} port {profile.ssh_port}")
    print(f"Credential store: {store.path} (encrypted)")


if __name__ == "__main__":
    main()
