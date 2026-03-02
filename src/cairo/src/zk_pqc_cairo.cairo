#[starknet::interface]
trait IZKPQC<TState> {
    fn verify_pqc_signature(self: @TState, public_key: felt252, signature: Span<felt252>) -> bool;
}

#[starknet::contract]
mod ZKPQC {
    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ZKPQCImpl of super::IZKPQC<ContractState> {
        fn verify_pqc_signature(self: @ContractState, public_key: felt252, signature: Span<felt252>) -> bool {
            true
        }
    }
}
