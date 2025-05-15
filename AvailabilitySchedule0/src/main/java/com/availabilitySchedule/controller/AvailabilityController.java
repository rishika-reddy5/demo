package com.availabilitySchedule.controller;

import com.availabilitySchedule.dto.AvailabilityDTO;
import com.availabilitySchedule.dto.DoctorAvailabilityRequest;
import com.availabilitySchedule.exception.AvailabilityNotFoundException;
import com.availabilitySchedule.service.AvailabilityService;
import com.availabilitySchedule.model.Availability;
import com.availabilitySchedule.model.Specialization;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/availability")
@Slf4j
@CrossOrigin(origins="http://localhost:3000")
public class AvailabilityController {

    @Autowired
    private AvailabilityService availabilityService;

    
    
    @PostMapping("/create/doctor")
    public ResponseEntity<String> createAvailabilityForDoctor(@RequestBody DoctorAvailabilityRequest request) {
        log.info("Creating manual availabilities for Doctor ID: {}", request.getDoctorId());
        availabilityService.createAvailabilityForDoctorId(
            request.getDoctorId(), request.getDoctorName(), request.getSpecialization(), request.getAvailability()
        );
        return ResponseEntity.ok("Availability slots added successfully.");
    }

//    @PostMapping("/create/doctor/{doctorId}/{doctorName}/{specialization}")
//    public void createAvailabilityForDoctorId(@PathVariable Long doctorId,
//            @PathVariable String doctorName, @PathVariable Specialization specialization) {
//        log.info("Creating Availabilities for Doctor ID: {}", doctorId);
//        availabilityService.createAvailabilityForDoctorId(doctorId, doctorName, specialization);
//    }

//    // ✅ Doctors submit availability manually
//    @PostMapping("/doctor/{doctorId}/set-availability")
//    public ResponseEntity<String> setDoctorAvailability(@PathVariable String doctorId, 
//                                                        @RequestParam String doctorName,
//                                                        @RequestParam Specialization specialization, 
//                                                        @RequestBody List<AvailabilityDTO> availabilityList) {
//        availabilityService.saveDoctorAvailability(doctorId, doctorName, specialization, availabilityList);
//        return ResponseEntity.ok("Availability slots added successfully.");
//    }
    
    @GetMapping("/{availabilityId}")
    public ResponseEntity<AvailabilityDTO> getAvailabilityById(@PathVariable Long availabilityId) {
        AvailabilityDTO availability = availabilityService.getAvailabilityById(availabilityId);
        if (availability == null) {
            throw new AvailabilityNotFoundException("Availability ID not found: " + availabilityId);
        }
        return ResponseEntity.ok(availability);
    }
    
    @GetMapping("/doctor/{doctorId}/date/{date}")
    public ResponseEntity<List<AvailabilityDTO>> getAvailabilityByDoctorIdAndDate(
            @PathVariable Long doctorId, @PathVariable LocalDate date) {
        
        List<AvailabilityDTO> availabilityDtos = availabilityService.getAvailabilityByDoctorIdAndDate(doctorId, date)
                .stream()
                .map(AvailabilityDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(availabilityDtos);
    }


    // ✅ Patients fetch doctor availability
    @GetMapping("/doctor/{doctorId}")
    public ResponseEntity<List<AvailabilityDTO>> getDoctorAvailability(@PathVariable Long doctorId) {
        List<AvailabilityDTO> availabilityDtos = availabilityService.getDoctorAvailability(doctorId)
                .stream()
                .map(AvailabilityDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(availabilityDtos);
    }

    // ✅ Patients fetch availability by specialization & date
    @GetMapping("/specialization/{specialization}/date/{date}")
    public ResponseEntity<List<AvailabilityDTO>> getAvailabilityBySpecializationAndDate(
            @PathVariable String specialization, @PathVariable LocalDate date) {

        List<AvailabilityDTO> availabilityDtos = availabilityService
            .getAvailabilityBySpecializationAndDate(Specialization.valueOf(specialization), date)
            .stream()
            .map(AvailabilityDTO::fromEntity)
            .collect(Collectors.toList());

        return ResponseEntity.ok(availabilityDtos);
    }


    // ✅ Patients book a time slot
    @PutMapping("/book/{availabilityId}")
    public ResponseEntity<String> bookTimeSlot(@PathVariable Long availabilityId) {
        availabilityService.bookTimeSlot(availabilityId);
        return ResponseEntity.ok("Time slot booked successfully.");
    }

    // ✅ Patients cancel a booked slot
    @PutMapping("/cancel/{availabilityId}")
    public ResponseEntity<String> cancelAvailability(@PathVariable Long availabilityId) {
        availabilityService.cancelAvailabilityStatus(availabilityId);
        return ResponseEntity.ok("Booking canceled successfully.");
    }

    // ✅ Admins view all availabilities
    @GetMapping("/doctors")
    public ResponseEntity<List<AvailabilityDTO>> viewAllAvailabilities() {
        List<AvailabilityDTO> availabilityDtos = availabilityService.viewAllAvailabilities()
                .stream()
                .map(AvailabilityDTO::fromEntity)
                .collect(Collectors.toList());

        return ResponseEntity.ok(availabilityDtos);
    }

    // ✅ Delete availability
    @DeleteMapping("/delete/{availabilityId}")
    public ResponseEntity<String> deleteAvailability(@PathVariable Long availabilityId) {
        availabilityService.deleteAvailability(availabilityId);
        return ResponseEntity.ok("Availability deleted successfully.");
    }
}
