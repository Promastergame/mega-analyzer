defmodule OmnisecServer.DebugSessions do
  @moduledoc """
  Ownership registry for interactive debugger sessions.

  The Rust NIF identifies sessions with sequential integer IDs and no
  notion of a client, so any API client could stop, step or read the
  memory of a session another client had started. This registry binds
  every session_id to the owner key derived from the request
  (`OmnisecServer.DebugController.session_owner/1`) and lets the
  controller reject foreign sessions with 403.
  """

  use GenServer

  @table __MODULE__

  def start_link(opts) do
    GenServer.start_link(__MODULE__, nil, Keyword.put_new(opts || [], :name, __MODULE__))
  end

  @impl true
  def init(_) do
    :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    {:ok, nil}
  end

  @doc "Registers `session_id` as owned by `owner`. Nil/non-positive IDs are ignored."
  def claim(owner, session_id) when is_integer(session_id) and session_id > 0 do
    true = :ets.insert(@table, {session_id, owner})
    :ok
  end

  def claim(_owner, _session_id), do: :ok

  @doc "Returns {:ok, owner} when the session is registered, :error otherwise."
  def owner_of(session_id) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, owner}] -> {:ok, owner}
      [] -> :error
    end
  end

  @doc "Forgets a session (after stop)."
  def release(session_id), do: :ets.delete(@table, session_id)
end
