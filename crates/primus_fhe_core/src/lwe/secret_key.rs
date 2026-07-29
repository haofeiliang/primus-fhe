use primus_integer::{FheUint, Size};
use primus_reduce::RingContext;
use rand::distr::Distribution;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    LweCiphertext, LweParameters, LweSecretKeyType, MultiMsgLweCiphertext, PlaintextEmbedding,
};

/// Represents a secret key for the Learning with Errors (LWE) cryptographic scheme.
#[derive(Clone)]
pub struct LweSecretKey<T: FheUint> {
    data: Vec<T>,
    distr: LweSecretKeyType,
}

impl<T: FheUint> Zeroize for LweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for LweSecretKey<T> {}

impl<T: FheUint> AsRef<[T]> for LweSecretKey<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T: FheUint> Size for LweSecretKey<T> {
    #[inline]
    fn byte_count(&self) -> usize {
        self.data.byte_count()
    }
}

impl<T: FheUint> LweSecretKey<T> {
    /// Creates a new [`LweSecretKey<T>`].
    #[inline]
    pub fn new(key: Vec<T>, distr: LweSecretKeyType) -> Self {
        Self { data: key, distr }
    }

    /// Returns the dimension of this [`LweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.data.len()
    }

    /// Returns the distribution of this [`LweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> LweSecretKeyType {
        self.distr
    }

    /// Generates a new [`LweSecretKey<T>`] with random values.
    #[inline]
    pub fn generate<R, M>(params: &LweParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let distr = params.secret_key_type();
        let key = match distr {
            LweSecretKeyType::Binary => primus_distr::sample_binary_values(params.dimension(), rng),
            LweSecretKeyType::Ternary => primus_distr::sample_ternary_values(
                params.cipher_modulus_minus_one(),
                params.dimension(),
                rng,
            ),
        };
        Self { data: key, distr }
    }

    /// Encrypts message into [`LweCiphertext<T>`].
    #[inline]
    pub fn encrypt<R, M, Msg>(
        &self,
        message: Msg,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        Msg: TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_with_embedding(message, params, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts a centered message into [`LweCiphertext<T>`].
    #[inline]
    pub fn encrypt_centered<R, M, Msg>(
        &self,
        message: Msg,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        Msg: TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_with_embedding(message, params, rng, PlaintextEmbedding::Centered)
    }

    /// Encrypts message into [`LweCiphertext<T>`] with the selected plaintext embedding.
    #[inline]
    pub fn encrypt_with_embedding<R, M, Msg>(
        &self,
        message: Msg,
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        Msg: TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        debug_assert_eq!(self.dimension(), params.dimension());

        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus();
        let uniform = params.cipher_modulus_uniform_distr();

        let mut ciphertext = LweCiphertext::generate_random_zero_sample(
            self.as_ref(),
            modulus,
            uniform,
            gaussian,
            rng,
        );
        params
            .plaintext_codec()
            .add_encode_value(ciphertext.b_mut(), message, embedding);

        ciphertext
    }

    /// Encrypts multiple messages using the secret key.
    #[inline]
    pub fn encrypt_multi_messages<R, M, Msg>(
        &self,
        messages: &[Msg],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        Msg: Copy + TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_multi_messages_with_embedding(
            messages,
            params,
            rng,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Encrypts multiple centered messages using the secret key.
    #[inline]
    pub fn encrypt_multi_messages_centered<R, M, Msg>(
        &self,
        messages: &[Msg],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        Msg: Copy + TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_multi_messages_with_embedding(
            messages,
            params,
            rng,
            PlaintextEmbedding::Centered,
        )
    }

    /// Encrypts multiple messages using the selected plaintext embedding.
    #[inline]
    pub fn encrypt_multi_messages_with_embedding<R, M, Msg>(
        &self,
        messages: &[Msg],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> MultiMsgLweCiphertext<T>
    where
        Msg: Copy + TryInto<T>,
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let dimension = params.dimension();

        debug_assert_eq!(self.dimension(), dimension);
        debug_assert!(messages.len() <= dimension);

        let gaussian = params.noise_distribution();
        let uniform = params.cipher_modulus_uniform_distr();
        let modulus = params.cipher_modulus();

        let mut data: Vec<T> = vec![T::ZERO; dimension + messages.len()];
        let (a, b) = data.split_at_mut(dimension);

        for (i, o) in a.iter_mut().zip(uniform.sample_iter(&mut *rng)) {
            *i = o;
        }

        b.iter_mut().enumerate().for_each(|(i, bi)| {
            *bi = self.multi_message_a_mul_s(a, i, dimension, modulus);
        });

        params
            .plaintext_codec()
            .add_encode_slice_assign(b, messages, embedding);

        for (bi, ei) in b.iter_mut().zip(gaussian.sample_iter(&mut *rng)) {
            modulus.reduce_add_assign(bi, ei);
        }

        MultiMsgLweCiphertext::new(data)
    }

    /// Encrypts multiple zeros using the secret key.
    #[inline]
    pub fn encrypt_multi_zeros<R, Modulus>(
        &self,
        zero_count: usize,
        params: &LweParameters<T, Modulus>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        Modulus: RingContext<T>,
    {
        let dimension = params.dimension();

        debug_assert_eq!(self.dimension(), dimension);
        debug_assert!(zero_count <= dimension);

        let gaussian = params.noise_distribution();
        let uniform = params.cipher_modulus_uniform_distr();
        let modulus = params.cipher_modulus();

        let mut data: Vec<T> = vec![T::ZERO; dimension + zero_count];
        let (a, b) = data.split_at_mut(dimension);

        a.iter_mut()
            .zip(uniform.sample_iter(&mut *rng))
            .for_each(|(i, o): (&mut T, T)| {
                *i = o;
            });

        b.iter_mut().enumerate().for_each(|(i, bi)| {
            *bi = self.multi_message_a_mul_s(a, i, dimension, modulus);
        });

        for (bi, ei) in b.iter_mut().zip(gaussian.sample_iter(&mut *rng)) {
            modulus.reduce_add_assign(bi, ei);
        }

        MultiMsgLweCiphertext::new(data)
    }

    /// Decrypts the [`LweCiphertext<T>`] back to message.
    #[inline]
    pub fn decrypt<M, Msg>(
        &self,
        cipher_text: &LweCiphertext<T>,
        params: &LweParameters<T, M>,
    ) -> Msg
    where
        Msg: TryFrom<T>,
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();

        let (a, b) = cipher_text.a_b();

        debug_assert_eq!(self.dimension(), params.dimension());
        debug_assert_eq!(a.len(), params.dimension());

        let a_mul_s = modulus.reduce_dot_product(a, self.as_ref());
        let plaintext = modulus.reduce_sub(b, a_mul_s);

        params.plaintext_codec().decode_value(plaintext)
    }

    /// Decrypts the [`LweCiphertext<T>`] back to message.
    #[inline]
    pub fn decrypt_with_noise<M, Msg>(
        &self,
        cipher_text: &LweCiphertext<T>,
        params: &LweParameters<T, M>,
    ) -> (Msg, T)
    where
        Msg: TryFrom<T>,
        M: RingContext<T>,
    {
        self.decrypt_with_noise_and_embedding(cipher_text, params, PlaintextEmbedding::Unsigned)
    }

    /// Decrypts the [`LweCiphertext<T>`] and returns the message with centered noise.
    #[inline]
    pub fn decrypt_centered_with_noise<M, Msg>(
        &self,
        cipher_text: &LweCiphertext<T>,
        params: &LweParameters<T, M>,
    ) -> (Msg, T)
    where
        Msg: TryFrom<T>,
        M: RingContext<T>,
    {
        self.decrypt_with_noise_and_embedding(cipher_text, params, PlaintextEmbedding::Centered)
    }

    /// Decrypts the [`LweCiphertext<T>`] and computes noise under the selected embedding.
    #[inline]
    pub fn decrypt_with_noise_and_embedding<M, Msg>(
        &self,
        cipher_text: &LweCiphertext<T>,
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
    ) -> (Msg, T)
    where
        Msg: TryFrom<T>,
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();

        let (a, b) = cipher_text.a_b();

        debug_assert_eq!(self.dimension(), params.dimension());
        debug_assert_eq!(a.len(), params.dimension());

        let a_mul_s = modulus.reduce_dot_product(a, self.as_ref());
        let plaintext = modulus.reduce_sub(b, a_mul_s);

        let message: T = params.plaintext_codec().decode_value(plaintext);
        let fresh: T = params.plaintext_codec().encode_value(message, embedding);

        (
            Msg::try_from(message)
                .map_err(|_| "out of range integral type conversion attempted")
                .unwrap(),
            modulus
                .reduce_sub(plaintext, fresh)
                .min(modulus.reduce_sub(fresh, plaintext)),
        )
    }

    /// Decrypts the [`MultiMsgLweCiphertext<T>`] back to message.
    #[inline]
    pub fn decrypt_multi_messages<M, Msg>(
        &self,
        cipher_text: &MultiMsgLweCiphertext<T>,
        params: &LweParameters<T, M>,
    ) -> Vec<Msg>
    where
        Msg: TryFrom<T>,
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();
        let dimension = params.dimension();

        debug_assert_eq!(self.dimension(), dimension);

        let (a, b) = cipher_text.a_b(dimension);

        debug_assert_eq!(a.len(), dimension);
        debug_assert!(b.len() <= dimension);

        let mut messages: Vec<T> = b
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let a_mul_s = self.multi_message_a_mul_s(a, i, dimension, modulus);
                modulus.reduce_sub(b, a_mul_s)
            })
            .collect();
        params.plaintext_codec().decode_slice_inplace(&mut messages);

        messages
            .into_iter()
            .map(|message| {
                Msg::try_from(message)
                    .map_err(|_| "out of range integral type conversion attempted")
                    .unwrap()
            })
            .collect()
    }

    #[inline]
    fn multi_message_a_mul_s<M>(&self, a: &[T], index: usize, dimension: usize, modulus: M) -> T
    where
        M: RingContext<T>,
    {
        if index == 0 {
            modulus.reduce_dot_product(a, self.as_ref())
        } else {
            modulus.reduce_dot_product_iter(
                a.iter()
                    .skip(dimension - index)
                    .map(|&ai| modulus.reduce_neg(ai))
                    .chain(a.iter().take(dimension - index).copied()),
                self.data.iter().copied(),
            )
        }
    }
}
