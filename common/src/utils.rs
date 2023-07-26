#[macro_export]
macro_rules! MASK {
    ($e:expr) => {
        {
             (1usize << $e) - 1usize
        }
    }
}

#[macro_export]
macro_rules! BIT {
    ($e:expr) => {
        {
            1usize<<$e
        }
    }
}