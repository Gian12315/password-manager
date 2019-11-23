use csv::{StringRecord, StringRecordsIter};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, prelude::*};
use std::path::Path;
use std::process;
extern crate cipher_crypt;

use cipher_crypt::{Cipher, Caesar};

macro_rules! menu {
    () => {
        println!("");
        println!("Actions possible: ");
        println!("1) Print all passwords");
        println!("2) Look up for an specific password");
        println!("3) Add a new password");
        println!("4) Delete a password");
        println!("5) Quit");
    };
}

fn main() {
    let file_name = Path::new("passwords.csv");
    if !file_name.exists() {
        if let Err(err) = create_file(file_name) {
            eprintln!("an error has ocurred: {}", err);
            process::exit(1);
        }
    }

    println!("Insert the master password");
    let mut string = String::new();
    io::stdin()
        .read_line(&mut string)
        .expect("Failed to read line");
    let string = string.trim();

    let hashed = calculate_hash(&string).to_string();
    let mut reader = csv::Reader::from_path(file_name).unwrap();
    let mut records = reader.records();
    let master = records.next().unwrap().unwrap();
    if !(hashed == master.get(1).unwrap()) {
        eprintln!("Master password doesn't match.");
    } else {
        loop {
            menu!();
            let mut reader = csv::Reader::from_path(file_name).unwrap();
            let records = reader.records();
            let mut choice = String::new();
            io::stdin()
                .read_line(&mut choice)
                .expect("Failed to read line");
            let choice: i32 = choice.trim().parse().expect("Failed to parse input");
            match choice {
                1 => print_all_passwords(records),
                2 => look_for_password(records),
                3 => add_password(file_name),
                4 => delete_password(file_name),
                5 => process::exit(0),
                _ => continue,
            }
        }
    }
}

fn create_file(file_name: &Path) -> Result<(), Box<dyn Error>> {
    println!("It seems is your first time using this program.");
    println!("Please insert a master password");
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim();
    let hashed_password = calculate_hash(&password);
    fs::write(
        file_name,
        format!("application,password\nmaster,{}", hashed_password),
    )?;
    Ok(())
}

fn print_all_passwords(records: StringRecordsIter<File>) {
    println!("Printing passwords...");
    records.for_each(|entry| {
        let entry = entry.unwrap();
        println!("{}: {}", entry.get(0).unwrap(), decrypt(entry.get(1).unwrap()));
    });
}

fn look_for_password(mut records: StringRecordsIter<File>) {
    println!("Input the password to look for");
    let mut app = String::new();
    io::stdin()
        .read_line(&mut app)
        .expect("Failed to read line");
    let app = app.trim();
    let found = records.find(|record| &record.as_ref().unwrap().get(0).unwrap() == &app);
    match found {
        Some(found) => {
            let found = found.unwrap();
            println!("{}: {}", found.get(0).unwrap(), decrypt(found.get(1).unwrap()));
        }
        None => println!("Password not found."),
    }
}

fn add_password(file_name: &Path) {
    println!("Input the application to save");
    let mut app = String::new();
    io::stdin()
        .read_line(&mut app)
        .expect("Failed to read line");
    println!("Input the password");
    let app = app.trim();
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read line");
    let password = password.trim();
    let password = encrypt(password);
    let mut records = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(file_name)
        .unwrap();
    let mut records: Vec<StringRecord> = records.records().map(|record| record.unwrap()).collect();
    let mut new_record = StringRecord::new();
    new_record.push_field(app);
    new_record.push_field(password.as_str());
    records.push(new_record);
    let mut writer = csv::Writer::from_path(file_name).unwrap();
    for record in records.iter() {
        writer.write_record(record).expect("Failed to write record");
    }
}

fn delete_password(file_name: &Path) {
    println!("Input the password to delete");
    let mut app = String::new();
    io::stdin()
        .read_line(&mut app)
        .expect("Failed to read line");
    let app = app.trim();
    let mut records = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(file_name)
        .unwrap();
    let new_records: Vec<StringRecord> = records
        .records()
        .filter(|record| &record.as_ref().unwrap().get(0).unwrap() != &app)
        .map(|record| record.unwrap())
        .collect();
    let mut writer = csv::Writer::from_path(file_name).unwrap();
    for record in new_records.iter() {
        writer.write_record(record).expect("Failed to write record");
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn encrypt(password: &str) -> String {
    let len = password.len();
    let c = Caesar::new(len);
    let encrypted = c.encrypt(password);
    encrypted.unwrap()
}

fn decrypt(password: &str) -> String {
    let len = password.len();
    let c = Caesar::new(len);
    let decrypted = c.decrypt(password);
    decrypted.unwrap()
}
