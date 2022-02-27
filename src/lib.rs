use crate::constants::*;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{clock, program_option::COption};
use anchor_spl::token::{self, TokenAccount, Token, Mint};
use std::convert::Into;
use std::convert::TryInto;
use metaplex_token_metadata::state::{Metadata};

declare_id!("7zR41kNXcdLoyj3yDgEZVmEPR1euvRkrFW1jSqR1Y7ri");
mod constants {
    pub const LP_TOKEN_MINT_PUBKEY: &str = "5DdHGhai9YwABGNjZUaY9aVBCuaYrdjG2skdoeroYZJN";
    pub const LP_DEPOSIT_REQUIREMENT: u64 = 10_000_000_000_000;
}

pub fn update_rewards(
    pool: &mut Account<Pool>,
    user: Option<&mut Box<Account<User>>>,
) -> Result<()> {
    let clock = clock::Clock::get().unwrap();
    
    if let Some(u) = user {
        let reward_per_token = pool.reward_per_token;
        let current_time: u64 = clock.unix_timestamp.try_into().unwrap();
        let mut reward_token_pending: u64 = 0;
        for i in 0..u.types.len() {
            let nft_type = u.types[i];
            let staked_time = u.staked_times[i];
            let diff_days: u64 = current_time.checked_sub(staked_time).unwrap()
                                    .checked_div(24 * 60 * 60).unwrap();
            let diff_times: u64 = staked_time.checked_sub(
                                                    staked_time.checked_div(24 * 60 * 60).unwrap()
                                                                .checked_mul(24 * 60 * 60).unwrap()
                                                ).unwrap();
            u.staked_times[i] = current_time.checked_sub(diff_times).unwrap();
            reward_token_pending = reward_token_pending.checked_add(
                                        reward_per_token.checked_mul(diff_days).unwrap()
                                                        .checked_div(nft_type as u64).unwrap()
                                    ).unwrap()
        }

        u.reward_token_pending = u.reward_token_pending.checked_add(reward_token_pending).unwrap();
        u.last_update_time = current_time;
    }
    
    Ok(())
}

#[program]
pub mod nft_staking {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        pool_nonce: u8,
        vault_nonce: u8,
    ) -> Result<()> {
        
        // lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_depositor.to_account_info(),
                to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                authority: ctx.accounts.lp_token_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, constants::LP_DEPOSIT_REQUIREMENT)?;

        let pool = &mut ctx.accounts.pool;

        pool.authority = ctx.accounts.authority.key();
        pool.nonce = pool_nonce;
        pool.paused = false;
        pool.lp_token_pool_vault = ctx.accounts.lp_token_pool_vault.key();
        pool.reward_mint = ctx.accounts.reward_mint.key();
        pool.reward_vault = ctx.accounts.reward_vault.key();
        pool.reward_per_token = 1_000_000_000_000;
        pool.user_stake_count = 0;

        let vault = &mut ctx.accounts.vault;
        vault.nonce = vault_nonce;
        vault.nfts = vec![];
        vault.candy_machines = vec![];
        vault.reward_types = vec![];
        vault.is_verify = vec![];
        
        Ok(())
    }

    pub fn set_reward_per_token(ctx: Context<SetRewardPerToken>, reward_per_token: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.reward_per_token = reward_per_token;

        Ok(())
    }

    pub fn create_user(ctx: Context<CreateUser>, nonce: u8) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.nft_mints = vec![];
        user.types = vec![];
        user.staked_times = vec![];
        user.pool = *ctx.accounts.pool.to_account_info().key;
        user.owner = *ctx.accounts.owner.key;
        user.reward_token_pending = 0;
        user.balance_staked = 0;

        let current_time = clock::Clock::get().unwrap().unix_timestamp.try_into().unwrap();

        user.last_update_time = current_time;
        user.nonce = nonce;

        let pool = &mut ctx.accounts.pool;
        pool.user_stake_count = pool.user_stake_count.checked_add(1).unwrap();

        Ok(())
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.paused = true;

        //lp refund
        let seeds = &[
            pool.to_account_info().key.as_ref(),
            &[pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_pool_vault.to_account_info(),
                to: ctx.accounts.lp_token_receiver.to_account_info(),
                authority: ctx.accounts.pool_signer.to_account_info(),
            },
            pool_signer,
        );

        token::transfer(cpi_ctx, ctx.accounts.lp_token_pool_vault.amount)?;
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::CloseAccount {
                account: ctx.accounts.lp_token_pool_vault.to_account_info(),
                destination: ctx.accounts.authority.to_account_info(),
                authority: ctx.accounts.pool_signer.to_account_info(),
            },
            pool_signer,
        );
        token::close_account(cpi_ctx)?;
        
        pool.lp_token_pool_vault = Pubkey::default();

        Ok(())
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.paused = false;

        //the prior token vault was closed when pausing
        pool.lp_token_pool_vault = ctx.accounts.lp_token_pool_vault.key();

        //lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_depositor.to_account_info(),
                to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                authority: ctx.accounts.lp_token_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, 10_000_000_000_000)?;
        
        Ok(())
    }

    pub fn add_candy_machine(
                                ctx: Context<ManageCandyMachine>, 
                                candy_machine: Pubkey, 
                                reward_type: u8,
                                is_verify: bool,
                            ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let index = vault.candy_machines.iter().position(|&x| x == candy_machine);
        if index == None {
            vault.candy_machines.push(candy_machine);
            vault.reward_types.push(reward_type);
            vault.is_verify.push(is_verify);
        } else {
            vault.reward_types[index.unwrap()] = reward_type;
            vault.is_verify[index.unwrap()] = is_verify;
        }
        Ok(())
    }

    pub fn remove_candy_machine(ctx: Context<ManageCandyMachine>, 
                                candy_machine: Pubkey, ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let index = vault.candy_machines.iter().position(|&x| x == candy_machine);
        if index != None {
            vault.candy_machines.remove(index.unwrap());
            vault.reward_types.remove(index.unwrap());
            vault.is_verify.remove(index.unwrap());
        }
        Ok(())
    }

    pub fn set_verify_candy_machine(ctx: Context<ManageCandyMachine>,
                                    candy_machine: Pubkey,
                                    is_verify: bool,) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let index = vault.candy_machines.iter().position(|&x| x == candy_machine);
        if index == None {
            return Err(ErrorCode::NotFoundCandyMachine.into());
        } else {
            vault.is_verify[index.unwrap()] = is_verify;
        }
        Ok(())
    }

    pub fn stake(ctx: Context<Stake>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        if pool.paused {
            return Err(ErrorCode::PoolPaused.into());
        }
        msg!("staking start");
        let metadata = Metadata::from_account_info(&ctx.accounts.metadata_info.to_account_info())?;
        let mut candy_flag = false;
        let mut reward_type = 0;
        let mut is_verify = false;
        msg!("Checking create");
        if let Some(cre) = metadata.data.creators {
            for c in cre {
                for i in 0..ctx.accounts.vault.candy_machines.len() {
                    let candy_machine = ctx.accounts.vault.candy_machines[i];
                    if c.address == candy_machine {
                        candy_flag = true;
                        reward_type = ctx.accounts.vault.reward_types[i];
                        is_verify = ctx.accounts.vault.is_verify[i];
                        break;
                    }
                }

                if candy_flag {
                    break;
                }
            }
        }
        if candy_flag != true {
            return Err(ErrorCode::CandyNotMatch.into());
        }
        msg!("Passed check candy machine");
        let user = &mut ctx.accounts.user;
        update_rewards(
            pool,
            Some(user),
        )
        .unwrap();
        msg!("updated rewards");
        user.balance_staked = user.balance_staked.checked_add(1 as u64).unwrap();
        msg!("Start nft transfer");
        // Transfer tokens into the stake vault.
        {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_from_account.to_account_info(),
                    to: ctx.accounts.stake_to_account.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(), //todo use user account as signer
                },
            );
            token::transfer(cpi_ctx, 1 as u64)?;
            msg!("End nft transfer");
            ctx.accounts.vault.nfts.push(ctx.accounts.stake_to_account.key());
            
            user.nft_mints.push(ctx.accounts.stake_to_account.mint);
            user.types.push(reward_type);

            let current_time = clock::Clock::get().unwrap().unix_timestamp.try_into().unwrap();
            user.staked_times.push(current_time);

            if is_verify == true {
                let seeds = &[
                    pool.to_account_info().key.as_ref(),
                    &[pool.nonce],
                ];
                let pool_signer = &[&seeds[..]];

                let cpi_ctx = CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.lp_token_pool_vault.to_account_info(),
                        to: ctx.accounts.lp_token_receiver.to_account_info(),
                        authority: ctx.accounts.pool_signer.to_account_info(),
                    },
                    pool_signer,
                );
                token::transfer(cpi_ctx, 1_000_000_000 as u64)?;
            }
        }

        Ok(())
    }

    pub fn unstake(ctx: Context<Stake>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user;
        let vault = &mut ctx.accounts.vault;
    
        let metadata = Metadata::from_account_info(&ctx.accounts.metadata_info.to_account_info())?;
        let mut candy_flag = false;
        let mut is_verify = false;

        if let Some(cre) = metadata.data.creators {
            for c in cre {
                for i in 0..vault.candy_machines.len() {
                    let candy_machine = vault.candy_machines[i];
                    if c.address == candy_machine {
                        candy_flag = true;
                        is_verify = vault.is_verify[i];
                        break;
                    }
                }

                if candy_flag {
                    break;
                }
            }
        }
        if candy_flag != true {
            return Err(ErrorCode::CandyNotMatch.into());
        }

        update_rewards(
            pool,
            Some(user),
        )
        .unwrap();
        user.balance_staked = user.balance_staked.checked_sub(1 as u64).unwrap();

        // Transfer tokens from the pool vault to user vault.
        {
            let seeds = &[
                pool.to_account_info().key.as_ref(),
                &[pool.nonce],
            ];
            let pool_signer = &[&seeds[..]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_to_account.to_account_info(),
                    to: ctx.accounts.stake_from_account.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
                pool_signer,
            );
            token::transfer(cpi_ctx, 1 as u64)?;

            let stake_to_account_key = ctx.accounts.stake_to_account.key();
            let stake_to_account_mint = ctx.accounts.stake_to_account.mint;

            let index = vault.nfts.iter().position(|x| *x == stake_to_account_key).unwrap();
            vault.nfts.remove(index);

            let index = user.nft_mints.iter().position(|x| *x == stake_to_account_mint).unwrap();
            user.nft_mints.remove(index);
            user.types.remove(index);
            user.staked_times.remove(index);

            if is_verify == true {
                let cpi_ctx = CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.lp_token_receiver.to_account_info(),
                        to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                        authority: ctx.accounts.owner.to_account_info(),
                    },
                );
                token::transfer(cpi_ctx, 1_000_000_000 as u64)?;
            }
        }

        Ok(())
    }

    pub fn claim(ctx: Context<ClaimReward>) -> Result<()> {
        let user_opt = Some(&mut ctx.accounts.user);
        update_rewards(
            &mut ctx.accounts.pool,
            user_opt,
        )
        .unwrap();

        let seeds = &[
            ctx.accounts.pool.to_account_info().key.as_ref(),
            &[ctx.accounts.pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];

        if ctx.accounts.user.reward_token_pending > 0 {
            let mut reward_amount = ctx.accounts.user.reward_token_pending;
            let vault_balance = ctx.accounts.reward_vault.amount;

            ctx.accounts.user.reward_token_pending = 0;
            if vault_balance < reward_amount {
                reward_amount = vault_balance;
            }

            if reward_amount > 0 {
                let cpi_ctx = CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.reward_vault.to_account_info(),
                        to: ctx.accounts.reward_account.to_account_info(),
                        authority: ctx.accounts.pool_signer.to_account_info(),
                    },
                    pool_signer,
                );
                token::transfer(cpi_ctx, reward_amount)?;
            }
        }

        Ok(())
    }

    pub fn close_user(ctx: Context<CloseUser>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.user_stake_count = pool.user_stake_count.checked_sub(1).unwrap();
        Ok(())
    }

    pub fn withdraw_stake(ctx: Context<WithdrawStake>, amount: u64) -> Result<()> {

        let pool = &ctx.accounts.pool;

        let mut withdraw_amount = amount;
        if amount > ctx.accounts.lp_token_pool_vault.amount {
            withdraw_amount = ctx.accounts.lp_token_pool_vault.amount;
        }
        //lp refund
        let seeds = &[
            pool.to_account_info().key.as_ref(),
            &[pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_pool_vault.to_account_info(),
                to: ctx.accounts.lp_token_receiver.to_account_info(),
                authority: ctx.accounts.pool_signer.to_account_info(),
            },
            pool_signer,
        );

        token::transfer(cpi_ctx, withdraw_amount)?;
        
        Ok(())
    }

    pub fn withdraw_reward(ctx: Context<WithdrawReward>, amount: u64) -> Result<()> {

        let seeds = &[
            ctx.accounts.pool.to_account_info().key.as_ref(),
            &[ctx.accounts.pool.nonce],
        ];
        let pool_signer = &[&seeds[..]];

        let mut withdraw_amount = amount;
        let vault_balance = ctx.accounts.reward_vault.amount;

        if vault_balance < withdraw_amount {
            withdraw_amount = vault_balance;
        }

        if withdraw_amount > 0 {
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.reward_vault.to_account_info(),
                    to: ctx.accounts.reward_account.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
                pool_signer,
            );
            token::transfer(cpi_ctx, withdraw_amount)?;
        }

        Ok(())
    }


    pub fn deposit_stake(ctx: Context<DepositStake>, amount: u64) -> Result<()> {
        let depositor_balance = ctx.accounts.lp_token_depositor.amount;
        let mut deposit_amount = amount;
        if amount > depositor_balance {
            deposit_amount = depositor_balance;
        }
        //lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.lp_token_depositor.to_account_info(),
                to: ctx.accounts.lp_token_pool_vault.to_account_info(),
                authority: ctx.accounts.lp_token_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, deposit_amount)?;
        
        Ok(())
    }


    pub fn deposit_reward(ctx: Context<DepositReward>, amount: u64) -> Result<()> {
        let depositor_balance = ctx.accounts.reward_depositor.amount;
        let mut deposit_amount = amount;
        if amount > depositor_balance {
            deposit_amount = depositor_balance;
        }
        //lp lockup
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.reward_depositor.to_account_info(),
                to: ctx.accounts.reward_vault.to_account_info(),
                authority: ctx.accounts.reward_deposit_authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, deposit_amount)?;
        
        Ok(())
    }

}

#[derive(Accounts)]
#[instruction(pool_nonce: u8, vault_nonce: u8)]
pub struct InitializePool<'info> {
    authority: UncheckedAccount<'info>,

    #[account(
        mut,
        // constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        // constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    lp_token_depositor: Box<Account<'info, TokenAccount>>,
    lp_token_deposit_authority: Signer<'info>,

    reward_mint: Box<Account<'info, Mint>>,
    #[account(
        constraint = reward_vault.mint == reward_mint.key(),
        constraint = reward_vault.owner == pool_signer.key(),
        constraint = reward_vault.close_authority == COption::None,
    )]
    reward_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool_nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    #[account(
        zero,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = vault_nonce,
        space = 10240,
    )]
    vault: Box<Account<'info, Vault>>,
    owner: Signer<'info>,
    
    token_program: Program<'info, Token>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetRewardPerToken<'info> {
    // Stake instance.
    #[account(
        mut,
        has_one = authority,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u8)]
pub struct CreateUser<'info> {
    // Stake instance.
    #[account(
        mut,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    // Member.
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref(),
            "user".as_bytes()
        ],
        bump = nonce,
        space = 10240, //// need to calculate space 
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    lp_token_receiver: Box<Account<'info, TokenAccount>>,

    #[account(
        mut, 
        has_one = authority,
        has_one = lp_token_pool_vault,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(
        mut,
        constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    // #[account(
    //     mut,
    //     constraint = lp_token_pool_vault.owner == pool_signer.key(),
    // )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    // #[account(
    //     mut,
    // )]
    lp_token_depositor: Box<Account<'info, TokenAccount>>,
    lp_token_deposit_authority: Signer<'info>,

    #[account(
        mut, 
        has_one = authority,
        constraint = pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositStake<'info> {
    #[account(
        mut,
        // constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        // constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    lp_token_depositor: Box<Account<'info, TokenAccount>>,
    lp_token_deposit_authority: Signer<'info>,

    #[account(
        mut, 
        has_one = authority,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositReward<'info> {
    #[account(
        mut,
        constraint = reward_vault.owner == pool_signer.key(),
    )]
    reward_vault: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        // constraint = lp_token_depositor.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap()
    )]
    reward_depositor: Box<Account<'info, TokenAccount>>,
    reward_deposit_authority: Signer<'info>,

    #[account(
        mut, 
        has_one = authority,
    )]
    pool: Box<Account<'info, Pool>>,
    authority: Signer<'info>,

    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
    )]
    vault: Box<Account<'info, Vault>>,
    #[account(
        mut,
        constraint = stake_to_account.owner == *pool_signer.key,
    )]
    stake_to_account: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut, 
        has_one = owner, 
        has_one = pool,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref(),
            "user".as_bytes()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    stake_from_account: Box<Account<'info, TokenAccount>>,
    metadata_info: UncheckedAccount<'info>,

    #[account(
        mut,
        // constraint = lp_token_pool_vault.mint == LP_TOKEN_MINT_PUBKEY.parse::<Pubkey>().unwrap(),
        constraint = lp_token_pool_vault.owner == pool_signer.key(),
    )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    lp_token_receiver: Box<Account<'info, TokenAccount>>,
    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimReward<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = reward_vault,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut, 
    )]
    vault: Box<Account<'info, Vault>>,
    #[account(mut)]
    reward_vault: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut,
        has_one = owner,
        has_one = pool,
        seeds = [
            owner.to_account_info().key.as_ref(),
            pool.to_account_info().key.as_ref(),
            "user".as_bytes()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    reward_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawStake<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = lp_token_pool_vault,
        constraint = pool.authority.key() == *owner.key
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut
    )]
    lp_token_pool_vault: Box<Account<'info, TokenAccount>>,

    owner: Signer<'info>,
    #[account(
        mut,
        constraint = lp_token_receiver.owner == *owner.key
    )]
    lp_token_receiver: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawReward<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = reward_vault,
        constraint = pool.authority.key() == *owner.key
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut
    )]
    reward_vault: Box<Account<'info, TokenAccount>>,

    owner: Signer<'info>,
    #[account(
        mut,
        constraint = reward_account.owner == *owner.key
    )]
    reward_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseUser<'info> {
    #[account(
        mut, 
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
        close = owner,
        has_one = owner,
        has_one = pool,
        seeds = [
            owner.to_account_info().key.as_ref(),
            pool.to_account_info().key.as_ref(),
            "user".as_bytes()
        ],
        bump = user.nonce,
        constraint = user.balance_staked == 0,
        constraint = user.reward_token_pending == 0,
    )]
    user: Account<'info, User>,
    owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ManageCandyMachine<'info> {
    // Stake instance.
    #[account(
        mut,
        has_one = authority,
        constraint = !pool.paused,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
    )]
    vault: Box<Account<'info, Vault>>,
    authority: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[account]
pub struct Pool {
    /// Priviledged account.
    pub authority: Pubkey,
    /// Nonce to derive the program-derived address owning the vaults.
    pub nonce: u8,
    /// Paused state of the program
    pub paused: bool,
    /// The vault holding users' lp
    pub lp_token_pool_vault: Pubkey,
    /// Mint of the reward token.
    pub reward_mint: Pubkey,
    /// Vault to store reward tokens.
    pub reward_vault: Pubkey,
    /// Rate of reward distribution.
    pub reward_per_token: u64,
    /// Users staked
    pub user_stake_count: u32,
}

#[account]
pub struct Vault {
    /// NFT accounts staked
    pub nfts: Vec<Pubkey>,
    pub candy_machines: Vec<Pubkey>,
    pub reward_types: Vec<u8>,
    pub is_verify: Vec<bool>,
    pub nonce: u8,
}

#[account]
#[derive(Default)]
pub struct User {
    /// Pool the this user belongs to.
    pub pool: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of token pending claim.
    pub reward_token_pending: u64,
    /// The amount of token pending claim.
    pub last_update_time: u64,
    /// The amount staked.
    pub balance_staked: u64,
    /// Signer nonce.
    pub nonce: u8,
    /// NFT mints stacked
    pub nft_mints: Vec<Pubkey>,
    pub types: Vec<u8>,
    pub staked_times: Vec<u64>,
}

#[error]
pub enum ErrorCode {
    #[msg("Insufficient funds to unstake.")]
    InsufficientFundUnstake,
    #[msg("Amount must be greater than zero.")]
    AmountMustBeGreaterThanZero,
    #[msg("Reward B cannot be funded - pool is single stake.")]
    SingleStakeTokenBCannotBeFunded,
    #[msg("Pool is paused.")]
    PoolPaused,
    #[msg("Duration cannot be shorter than one day.")]
    CandyNotMatch,
    #[msg("This nft was not created from our candy machine.")]
    DurationTooShort,
    #[msg("Not found candy machine.")]
    NotFoundCandyMachine,
}
