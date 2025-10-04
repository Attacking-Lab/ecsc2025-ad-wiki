# Scoring Formula

In Jeopardy CTFs, dynamic scoring is scoring is used to infer the difficulty
of a challenge by the number of teams who are able to solve it. This scoring
formula applies this concept to A/D.

In effect, each round is treated as a Jeopardy CTF with the following challenges:

- For each flag you capture, you receive **ATK points** based on the number
  of teams that capture that flag.
- For each service and each flagstore, you receive **DEF points** for each
  actively exploiting team that you did not get your flag captured by,
  proportional to the amount of teams whose flag that team did capture.

Additionally, you gain a **fixed amount of SLA points** for each flag available
from the *retention period*, as long as the checker status is `SUCCESS` or `RECOVERING`.

## Checker Status

The checker returns one of the following results for each service:

- <span class=hl-success>`SUCCESS`</span> if all flags could be successfully deployed and
retrieved, and functionality checks were successful.
- <span class=hl-mumble>`MUMBLE`</span> if any checks for the current round failed.
- <span class=hl-recovering>`RECOVERING`</span> if checks for the current round succeed,
  but flag from the retention period is missing.
- <span class=hl-offline>`OFFLINE`</span> if it failed to establish a connection to the service.
- <span class=hl-error>`INTERNAL_ERROR`</span> if an internal error occurred. **Please notify us with context in a ticket.**


## Implementation

The following is an edited snippet which calculates the final scoreboard from a series of rounds.

The full implementation can be play-tested using
[our simulator](https://github.com/attacking-lab/scoring-playground) (PRs welcome!).

```python3
SCALING = 10

def jeopardy(x):
    return int(SCALING * (30 / (29 + max(x, 1))) ** 3)

# Pre-compute victims for each service/flagstore/attacker,
# attributed back to the round in which the stolen flag was deployed
attacked_teams: typing.MutableMapping[
    tuple[RoundId, ServiceName, FlagStoreId],
    typing.MutableMapping[TeamName, set[TeamName]]
] = collections.defaultdict(lambda: collections.defaultdict(set))
for round_id, round_data in ctf.enumerate():
    for team, team_data in round_data.items():
        for flag_id in team_data.flags_captured:
            flag = ctf.flags[flag_id]
            if flag.owner == team or flag.owner == self.nop_team:
                continue
            attacked_teams[(flag.round_id, flag.service, flag.flagstore)][team].add(ctf.flags[flag_id].owner)

scoreboard: Scoreboard = collections.defaultdict(Score.default)
for round_id, round_data in ctf.enumerate():
    # SLA flags:
    #   You gain a fixed SLA score for each flag available from the
    #   retention period, as long as the status is SUCCESS or RECOVERING.
    for team, team_data in round_data.items():
        sla = 0.0
        for service, state in team_data.service_states.items():
            flagstores = len(ctf.services[service].flagstores)
            max_flags = ctf.config.flag_retention * flagstores
            if state == ServiceState.SUCCESS:
                present = max_flags
            elif state == ServiceState.RECOVERING:
                present = len(team_data.flags_retrieved[service])
            else:
                present = 0
            flagstores = len(ctf.services[service].flagstores)
            sla += SCALING * present / max_flags * flagstores
        scoreboard[team] += Score.default(sla=sla)

    # Attack flags:
    #   For each flag that is still valid, if you capture that flag
    #   you get points scaled by how many teams captured that flag.
    for team, team_data in round_data.items():
        attack = 0.0
        for flag_id in team_data.flags_captured:
            flag = ctf.flags[flag_id]
            if flag.owner == team:
                continue
            attack += jeopardy(ctf.flag_captures[flag_id].count)
        scoreboard[team] += Score.default(attack=attack)

    # Estimate the number of playing teams
    online = set()
    for team, team_data in round_data.items():
        if team != self.nop_team and any(s != ServiceState.OFFLINE for s in team_data.service_states):
            online.add(team)

    # Defense flags:
    #   For each flag that is still valid, for each attacking team,
    #   if you did not get exploited by that team,
    #   you get points scaled by the number of teams that that team did not exploit.
    for service, flagstore in ctf.flagstores:
        victims_of = attacked_teams[(round_id, service, flagstore)]
        attackers = [team for team in ctf.teams if len(victims_of[team]) > 0]
        for attacker in attackers:
            if attacker == self.nop_team:
                continue
            max_victims = len(online - {attacker,})
            not_exploited = max_victims - len(victims_of[attacker])
            value = jeopardy(not_exploited) * max_victims / len(attackers)
            for other, other_data in round_data.items():
                if other == attacker or other in victims_of[attacker]:
                    continue
                if other_data.service_states[service] not in (ServiceState.SUCCESS, ServiceState.RECOVERING):
                    continue
                scoreboard[other] += Score.default(defense=value)

```

## Review

- Since the capture count of each stored flag determines its worth,
  attackers are rewarded based on how difficult it is to exploit each specific team.
- The same goes for defense; a patch is rewarded based on the amount of other
  teams which were not able to defend against the exploiting team.
- Not attacking a team effectively gives that team defense points, thus there
  exists an additional incentive to attack as many teams as possible,
  beyond attack points. Teams will need to decide if the points gained from
  not attacking a team offset the expected loss of having the exploit stolen.
- Crucially, even though defending is more highly weighted than usual formulas,
  it never earns a team more points than the exploiting team
  receives from attacking (see <a href=https://www.desmos.com/calculator/d6mceqjxa0>
  https://www.desmos.com/calculator/d6mceqjxa0</a> with variables (`v`:
  victims, `a`: attackers, `n`: active teams).
  

