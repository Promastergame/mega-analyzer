defmodule BitArena.Match do
  @moduledoc """
  The authoritative game world for a single match.

  It owns every position, coin and score, advances the simulation on a fixed
  tick, and broadcasts snapshots to the player sockets. Clients only ever send
  *intent* (a desired direction); the server alone decides what actually
  happens. That is the golden rule of an authoritative server — and the reason a
  private server has to emulate this loop faithfully to be believable.
  """

  use GenServer, restart: :temporary
  require Logger

  alias BitArena.Leaderboard

  @player_radius 14
  @coin_radius 18
  @base_speed 260.0
  @coin_target 6
  @finish_grace_ms 6_000

  # ── Client API ───────────────────────────────────────────────────

  def start_link(%{name: name} = args) do
    GenServer.start_link(__MODULE__, args, name: via(name))
  end

  @doc "Registry tuple used to address a match by name."
  def via(name), do: {:via, Registry, {BitArena.MatchRegistry, name}}

  @doc "Add a player to the match. Returns `:ok` or `:full`."
  def add_player(match, player), do: GenServer.call(match, {:add_player, player})

  @doc "Submit a player's movement intent (fire-and-forget)."
  def input(match, id, cmd), do: GenServer.cast(match, {:input, id, cmd})

  @doc "Can this match still accept players?"
  def open?(match), do: GenServer.call(match, :open?)

  @doc "Current world snapshot — the same payload the sockets receive each tick."
  def snapshot(match), do: GenServer.call(match, :snapshot)

  # ── Server callbacks ─────────────────────────────────────────────

  @impl true
  def init(%{name: name}) do
    arena = BitArena.config(:arena, %{width: 1280, height: 720})
    tick_ms = max(div(1000, BitArena.config(:tick_hz, 20)), 1)

    state = %{
      name: name,
      status: :waiting,
      players: %{},
      coins: [],
      tick: 0,
      width: arena.width,
      height: arena.height,
      win_score: BitArena.config(:win_score, 30),
      round_ms: BitArena.config(:round_ms, 120_000),
      tick_ms: tick_ms,
      started_at: nil
    }

    Process.send_after(self(), :tick, tick_ms)
    {:ok, %{state | coins: spawn_coins(state, @coin_target)}}
  end

  @impl true
  def handle_call({:add_player, player}, _from, state) do
    if full?(state) do
      {:reply, :full, state}
    else
      # Monitoring the socket process is all the disconnect handling we need:
      # when the WebSocket dies, OTP tells us and the player simply leaves.
      ref = Process.monitor(player.socket)
      {x, y} = random_point(state)

      p = %{
        id: player.id,
        name: player.name,
        socket: player.socket,
        ref: ref,
        x: x * 1.0,
        y: y * 1.0,
        dx: 0.0,
        dy: 0.0,
        score: 0,
        skin: player.perks.skin,
        speed_mult: player.perks.speed_mult,
        coin_mult: player.perks.coin_mult,
        trail: player.perks.trail
      }

      state = put_in(state.players[player.id], p)
      state = if state.status == :waiting, do: start_round(state), else: state
      send(player.socket, {:push, welcome(state, p)})
      {:reply, :ok, state}
    end
  end

  def handle_call(:open?, _from, state), do: {:reply, not full?(state), state}
  def handle_call(:snapshot, _from, state), do: {:reply, snapshot_payload(state), state}

  @impl true
  def handle_cast({:input, id, %{"dir" => [dx, dy]}}, state)
      when is_map_key(state.players, id) do
    {ux, uy} = unit(dx * 1.0, dy * 1.0)
    {:noreply, update_in(state.players[id], &%{&1 | dx: ux, dy: uy})}
  end

  def handle_cast({:input, _id, _cmd}, state), do: {:noreply, state}

  @impl true
  def handle_info(:tick, %{status: :running} = state) do
    state =
      state
      |> integrate()
      |> collect_coins()
      |> Map.update!(:tick, &(&1 + 1))

    broadcast(state, snapshot_payload(state))

    cond do
      champion = champion(state) -> finish(state, champion)
      round_expired?(state) -> finish(state, leader(state))
      true -> {:noreply, schedule_tick(state)}
    end
  end

  def handle_info(:tick, state) do
    # Waiting for players: keep a heartbeat so the round can start the moment
    # somebody joins, without add_player having to own the timer.
    {:noreply, schedule_tick(state)}
  end

  def handle_info(:shutdown, state), do: {:stop, :normal, state}

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    state =
      case Enum.find(state.players, fn {_id, p} -> p.ref == ref end) do
        {id, p} ->
          Logger.info("match #{state.name}: #{p.name} disconnected")
          %{state | players: Map.delete(state.players, id)}

        nil ->
          state
      end

    if state.status == :running and map_size(state.players) == 0 do
      Logger.info("match #{state.name}: empty, closing")
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Simulation ───────────────────────────────────────────────────

  defp schedule_tick(state) do
    Process.send_after(self(), :tick, state.tick_ms)
    state
  end

  defp start_round(state) do
    Logger.info("match #{state.name}: round start")
    %{state | status: :running, started_at: now_ms()}
  end

  # Fixed-step integration of the intent each client last sent us.
  defp integrate(state) do
    dt = state.tick_ms / 1000.0

    players =
      Map.new(state.players, fn {id, p} ->
        speed = @base_speed * p.speed_mult
        nx = clamp(p.x + p.dx * speed * dt, @player_radius, state.width - @player_radius)
        ny = clamp(p.y + p.dy * speed * dt, @player_radius, state.height - @player_radius)
        {id, %{p | x: nx, y: ny}}
      end)

    %{state | players: players}
  end

  defp collect_coins(state) do
    {players, coins, taken_any} =
      Enum.reduce(state.players, {state.players, state.coins, false}, fn {id, p},
                                                                        {acc, coins, hit} ->
        {taken, rest} = Enum.split_with(coins, &touching?(p, &1))

        case taken do
          [] ->
            {acc, coins, hit}

          coins_taken ->
            gained = coins_taken |> Enum.map(& &1.value) |> Enum.sum()
            {put_in(acc[id].score, p.score + gained * p.coin_mult), rest, true}
        end
      end)

    coins = if taken_any, do: replenish(state, coins), else: coins
    %{state | players: players, coins: coins}
  end

  defp touching?(p, coin) do
    reach = @player_radius + @coin_radius
    dx = p.x - coin.x
    dy = p.y - coin.y
    dx * dx + dy * dy <= reach * reach
  end

  defp replenish(state, coins) do
    missing = @coin_target - length(coins)
    if missing > 0, do: coins ++ spawn_coins(state, missing), else: coins
  end

  defp champion(state) do
    state.players
    |> Enum.filter(fn {_id, p} -> p.score >= state.win_score end)
    |> case do
      [] -> nil
      reached -> reached |> Enum.max_by(fn {_id, p} -> p.score end) |> elem(1)
    end
  end

  defp leader(state) do
    if map_size(state.players) == 0 do
      nil
    else
      {_id, p} = Enum.max_by(state.players, fn {_id, p} -> p.score end)
      p
    end
  end

  defp round_expired?(%{started_at: nil}), do: false
  defp round_expired?(state), do: now_ms() - state.started_at >= state.round_ms

  defp finish(state, winner) do
    scores = Map.new(state.players, fn {_id, p} -> {p.name, p.score} end)
    winner_name = if winner, do: winner.name, else: nil

    Leaderboard.record(scores, winner_name)

    broadcast(state, %{
      type: "game_over",
      match: state.name,
      winner: winner_name,
      scores: scores,
      board: Leaderboard.top(10)
    })

    Logger.info("match #{state.name}: game over, winner=#{winner_name || "nobody"}")
    Process.send_after(self(), :shutdown, @finish_grace_ms)
    {:noreply, %{state | status: :finished}}
  end

  # ── Payloads ────────────────────────────────────────────────────

  defp welcome(state, p) do
    %{
      type: "welcome",
      you: p.id,
      name: p.name,
      match: state.name,
      skin: p.skin,
      arena: %{width: state.width, height: state.height},
      win_score: state.win_score,
      tick_hz: BitArena.config(:tick_hz, 20)
    }
  end

  defp snapshot_payload(state) do
    %{
      type: "state",
      tick: state.tick,
      status: state.status,
      players:
        Enum.map(state.players, fn {_id, p} ->
          %{
            id: p.id,
            name: p.name,
            x: Float.round(p.x, 1),
            y: Float.round(p.y, 1),
            score: p.score,
            skin: p.skin,
            trail: p.trail
          }
        end),
      coins: Enum.map(state.coins, fn c -> %{id: c.id, x: c.x, y: c.y, v: c.value} end)
    }
  end

  defp broadcast(state, payload) do
    Enum.each(state.players, fn {_id, p} -> send(p.socket, {:push, payload}) end)
  end

  # ── Helpers ─────────────────────────────────────────────────────

  defp full?(state) do
    state.status == :finished or
      map_size(state.players) >= BitArena.config(:max_players_per_match, 8)
  end

  defp spawn_coins(state, n) when n > 0 do
    Enum.map(1..n, fn _ ->
      {x, y} = random_point(state)
      %{id: :erlang.unique_integer([:positive]), x: x, y: y, value: Enum.random([1, 1, 1, 2, 3])}
    end)
  end

  defp spawn_coins(_state, _n), do: []

  defp random_point(state) do
    {
      :rand.uniform(state.width - 2 * @player_radius) + @player_radius,
      :rand.uniform(state.height - 2 * @player_radius) + @player_radius
    }
  end

  # Clamp the client's requested direction to a unit vector: this is what stops
  # a patched client from simply sending dir = [9999, 9999] and teleporting.
  defp unit(0.0, 0.0), do: {0.0, 0.0}

  defp unit(dx, dy) do
    mag = :math.sqrt(dx * dx + dy * dy)
    if mag <= 1.0, do: {dx, dy}, else: {dx / mag, dy / mag}
  end

  # Always returns a float: `max(13.5, 14)` would otherwise hand back the
  # integer 14 and make Float.round/2 raise on the next snapshot.
  defp clamp(v, lo, hi), do: (v |> max(lo) |> min(hi)) * 1.0

  defp now_ms, do: System.monotonic_time(:millisecond)
end
